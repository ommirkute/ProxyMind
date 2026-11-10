---
name: triage_findings
title: Triage suspected findings
description: Go through suspected findings from scans, reproduce or refute each one, and prove the real ones.
args: focus
---
Goal: turn the scanner's suspected findings into proven findings or false positives. {{focus}}

1. `finding_list` with status `suspected`. Group them by class; start with high severity.
2. For each one, read its evidence exchanges with `exchange_get` (token-budgeted view), and decide what would prove it:
   - access control → `proof_run` oracle `differential_authz`;
   - out-of-band (SSRF, XXE, blind injection) → oracle `oast`;
   - time-based injection → oracle `timing`;
   - reflected/DOM XSS → oracle `reflection` (runs it in a headless browser).
3. Record a hypothesis (`hypothesis_create`) before each test, then run the proof. Update the finding: `finding_update` to `proven` with the proof id, or to `false_positive` with the reason.
4. Where no oracle fits (mass assignment, CSRF, cache issues), reproduce by hand with `replay_send`, one change at a time, and keep the exchanges as evidence.
5. `finding_retest` re-runs a proof later, for example after a fix.

Don't mark anything proven without a proof or a clear reproduction you can point to.
