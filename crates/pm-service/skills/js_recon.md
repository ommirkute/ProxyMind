---
name: js_recon
title: JavaScript recon
description: Read the app's scripts for API routes, parameters and secrets no page shows, then test the new routes.
args: focus
---
Goal: widen the attack surface from what the front end's JavaScript reveals. {{focus}}

1. `engage_scripts` lists external and inline scripts. Make sure the main bundles are recorded (browse the app, or `discover_content` with their paths).
2. `engage_js_endpoints`: endpoints with `known: false` have not appeared in traffic yet. Note methods and parameters.
3. `engage_comments` on scripts: look for old endpoints, debug flags, keys and internal host names. Secrets show as placeholders; report the location, not the value.
4. For each new GET endpoint in scope: `replay_send` it once as a logged-in user and once anonymously. Anything that answers 2xx anonymously, or returns more data than the UI uses, gets a hypothesis.
5. Run `scan_active` on the new endpoints that take parameters, and add them to the access-control checks (`authz_candidates` picks them up once they are in the model).
6. For POST/PUT/DELETE routes, describe the test to the person and wait for approval before sending.
