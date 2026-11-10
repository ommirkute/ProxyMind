---
name: idor_sweep
title: Access-control sweep (IDOR / BOLA / BFLA)
description: Try every object one test user owns as the other users and anonymously, over REST and GraphQL, and prove each leak.
args: focus
---
Goal: find every place where one user can read or change another user's data (broken object-level authorization), or reach a function meant for another role (broken function-level authorization). {{focus}}

1. Call `roe_get`. Note what is in scope and what needs approval. Call `identity_list`: you need at least two users of the same role (plus an admin, if there is one). If fewer exist, stop and ask the person to capture them (`identity_capture`).
2. Call `model_get` and look at operations with an object type and objects with an owner. If it is thin, browse more of the app first (or `crawl`).
3. Call `authz_candidates`. For each candidate, call `hypothesis_create` (vuln_class `idor` or `bfla`), then `authz_check` with the owner's exchange.
4. For every `same_as_owner` verdict: check that an anonymous caller is refused (a public object is not a leak), `finding_create`, then `proof_run` with oracle `differential_authz`. Update the hypothesis to confirmed or refuted.
5. Writes: for PUT/PATCH/DELETE on an owned object, propose the test to the person first (it changes data); with approval, replay it as the other user with `replay_send` and read the object back as its owner to confirm the change landed.
6. GraphQL: if `site_map` shows a GraphQL endpoint, `graphql_import` it and repeat step 4 for queries that take an id.
7. Finish with `coverage` and list operations not yet checked.

Report only proven findings as confirmed; everything else stays suspected with what you saw.
