---
name: file_upload
title: File upload review
description: Test upload endpoints for stored XSS through HTML/SVG, executable files, path traversal in names and missing type checks. Needs approval.
args: focus
---
Goal: check that uploads can't run code or reach other users' browsers. {{focus}}

1. Find multipart requests in history (`history_search` with `reqheader:content-type~multipart`).
2. Explain the test to the person and wait for approval: uploads are stored on the target.
3. `scan_active` with checks `["file_upload"]` on the recorded upload: it tries HTML, SVG and script files with harmless markers and looks for where they are served.
4. By hand with `replay_send`: a name with `../`, a double extension (`a.png.html`), a wrong Content-Type, and an oversized file only if the person agrees.
5. When a file is served back: check its Content-Type and Content-Disposition, and whether it is on the app's own origin (stored XSS) or a sandbox domain. Prove XSS with `proof_run` oracle `reflection` (a headless browser).
6. List what you uploaded so the person can clean it up.
