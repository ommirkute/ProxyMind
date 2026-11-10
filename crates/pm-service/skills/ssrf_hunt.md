---
name: ssrf_hunt
title: Server-side request forgery hunt (out-of-band)
description: Find parameters and headers the server fetches or looks up, using Collaborator callbacks, including callbacks that arrive late.
args: focus
---
Goal: find places where the server makes requests to addresses an attacker chooses. {{focus}}

1. Check the out-of-band setup: `collaborator_interactions` with a small limit. If no listener is configured, ask the person to start one (Collaborator page or `proxymind oast-server`) and, ideally, delegate a DNS zone to it: DNS catches lookups that never turn into HTTP requests.
2. Candidates: `engage_analyze` lists parameters; look for names like url, uri, link, callback, webhook, image, avatar, feed, host, domain, path, file, and for values that are URLs or host names. `engage_js_endpoints` may reveal fetch-style endpoints no page links to.
3. Run `scan_active` with checks `["ssrf_oob", "xxe_oob"]` on each candidate request. It also adds pingback headers (Referer, X-Forwarded-For, X-Forwarded-Host, True-Client-IP, Contact, X-Wap-Profile) that log processors fetch.
4. For manual tests, `collaborator_payload` with a note naming the parameter, put the URL (or DNS name) in it with `replay_send`, then check `collaborator_interactions` for that token.
5. Callbacks can come minutes or hours later (queues, nightly jobs): a late callback on a scanner probe becomes a finding by itself. Check `finding_list` again before you finish.
6. For each callback: `finding_create` (vuln_class `ssrf`), note the protocol (DNS only means a lookup; HTTP means a fetch) and the source address, then `proof_run` with oracle `oast` to reproduce it.

Never point payloads at internal addresses to "see what happens" without the person's approval: reaching internal services can be destructive.
