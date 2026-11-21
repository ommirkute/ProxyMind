# ProxyMind in CI: `proxymind ci`

One command for a pipeline. It loads a rules-of-engagement file, checks that the target is in scope, logs in the
identities it was given, imports an API description if there is one, crawls, runs the active scanner with a profile,
proves what it can, compares the findings with a baseline, writes SARIF, JUnit and JSON files and exits with a code a
pipeline can act on.

```bash
proxymind ci --roe security/roe.yaml \
             --target https://staging.example.com/ \
             --baseline security/proxymind-baseline.json \
             --sarif proxymind.sarif --junit proxymind.xml --json proxymind.json \
             --profile default --budget-minutes 30 --max-requests 20000
```

Examples to copy: [`examples/ci/github-actions.yml`](../examples/ci/github-actions.yml) (SARIF goes to GitHub code
scanning) and [`examples/ci/gitlab-ci.yml`](../examples/ci/gitlab-ci.yml). To re-check findings after they were fixed,
without scanning again, see `proxymind regress run` in [`docs/agents.md`](agents.md#regression-tests-for-ci).

Only run it against systems you are allowed to test. The rules-of-engagement file is how you say which.

## What a run does

1. **Rules and scope.** The ROE file is required (CI never runs without an explicit scope). The target (`--target`, or
   the first scope entry without a wildcard) must be in scope, or the run stops with an error before a request is sent.
2. **A fresh project.** A new project in memory, discarded afterwards. `--project path.pmproj` uses (and creates) a file
   instead, to keep the traffic and findings for the UI; see "Safety".
3. **The target answers.** One GET to the target. No answer (or a 502/503/504) ends the run as "not clean".
4. **Identities** (optional). `--identity-file` defines them, `--identity` picks them; each is logged in and its session
   checked. A failed login ends the run as "not clean".
5. **API description** (optional). `--openapi spec.json` is imported and its GET examples sent, so the scanner knows
   those operations.
6. **Content discovery** (every profile except `light`): hidden files, `.git`, debug endpoints, an API description.
7. **Crawl and scan.** The profile's crawl (JavaScript run in a headless browser when Chromium is installed, unless
   `--no-browser`), then the active checks on every operation found (the same task as `proxymind scan-task run`).
8. **Access control** when two or more identities were given: each is crawled and the cross-user checks run.
9. **Proving.** Suspected findings get the oracle that fits their class (error-based SQL injection, reflected XSS in a
   headless browser, path traversal, open redirect, header injection, …); the ones that hold become `proven`.
10. **Results.** Findings of this run are fingerprinted, compared with the baseline and written out.

Profiles are the ones of `proxymind scan-profile list`: `light` (a few fast checks, short crawl), `default`, `thorough`
(adds smuggling, upload and race checks, which need the destructive tier, see below) and `api-only` (no crawl: give it
`--openapi`, or let discovery find the description).

## Exit codes

| Code | Meaning |
| --- | --- |
| **0** | The run finished and found no new finding at or above `--fail-on` and `--min-severity`. |
| **1** | New findings that fail the run: not in the baseline, at least `--min-severity`, and proven (with `--fail-on suspected`, also suspected). This wins over 2: a real problem is never hidden behind an unfinished run. |
| **2** | The run could not finish properly, so it says nothing about the target. Causes: the ROE is invalid or the target is out of scope; the target is unreachable; a login failed; the request or time budget ran out before the scan finished; the rules of engagement skipped checks or operations (unless `--allow-skipped`) or nothing was found to scan; a file could not be read or written; a usage error. |

A run is never reported clean when the scan did not really run (the same stance as `proxymind regress run`, where a
skipped test fails the run). The summary says `INCOMPLETE: <why>` for every reason, `complete: false` in the JSON, an
`error` test case in the JUnit file and `executionSuccessful: false` in the SARIF invocation, and all the files are still
written, so a pipeline can upload them with `if: always()`.

`--fail-on none` reports everything and never exits 1 (it still exits 2 for an unfinished run).

## Rules of engagement for CI

CI acts as the actor **`ci:pipeline`**, a kind of its own, with its own section in the ROE:

```yaml
version: 1
scope:
  include: ["https://staging.example.com/"]
  exclude: ["https://staging.example.com/logout"]
limits:
  max_rps_per_host: 20
  max_concurrency: 4
tiers:
  ci:
    active_intrusive: allow     # scan probes (payloads in parameters). Needed to scan at all.
    # destructive: allow        # smuggling, uploads, races: only on a throwaway environment
```

Nobody can approve anything in a pipeline, so **CI never approves**. What the ROE leaves at `approve` for CI is
**skipped and reported**, never granted; `deny` is skipped too. The defaults for `ci` are: read, passive and active-safe
(plain GETs) allowed, active-intrusive `approve`, destructive `deny`. Without `tiers.ci.active_intrusive: allow` a run
crawls, reports "scan probes are not sent" and exits 2. The thorough profile's destructive-tier checks are left out (and
reported) unless `tiers.ci.destructive` is `allow`. A skip makes the run exit 2 unless `--allow-skipped` says you accept
it; it is still printed. The scope, time windows, engagement dates, denied networks and rate limits apply as always.

## Options

| Option | |
| --- | --- |
| `--roe FILE` | Required. |
| `--target URL` | Must be in scope. Default: the first scope entry without a wildcard. |
| `--baseline FILE` | Known findings; only findings not in it fail the run. A missing or unreadable file is an error (exit 2). |
| `--write-baseline FILE` | Write this run's proven findings as a baseline (`--baseline-suspected`: suspected ones too). Not written when the run did not finish. |
| `--sarif FILE`, `--junit FILE`, `--json FILE` | Output files. |
| `--fail-on proven\|suspected\|none` | Default `proven`. |
| `--min-severity info\|low\|medium\|high\|critical` | Default `low`. |
| `--profile NAME` | Default `default`. |
| `--budget-minutes N`, `--max-requests N` | Hard caps (see below). |
| `--identity NAME` (repeatable), `--identity-file FILE` (repeatable) | Logins. |
| `--openapi FILE` | OpenAPI or Swagger description to import. |
| `--project PATH` | Use this project file instead of a fresh one. |
| `--insecure` | Do not verify the target's TLS certificate. |
| `--no-browser` | Crawl without a headless browser. |
| `--allow-skipped` | Accept skips by the rules and an empty crawl. |

`proxymind ci --help` repeats the exit codes.

## Baselines

A baseline is a JSON file of known findings, committed next to the pipeline and reviewed like code:

```bash
# once, on a clean checkout of the staging environment (exits 1 if it found something, so allow that):
proxymind ci --roe security/roe.yaml --write-baseline security/proxymind-baseline.json || true
git add security/proxymind-baseline.json
```

- **new**: in this run, not in the baseline. These fail the run when they are severe enough and proven (or suspected,
  with `--fail-on suspected`).
- **unchanged**: in both. Never fails.
- **fixed**: in the baseline, not found now. Only reported (stdout, JSON `fixed`, SARIF `baselineState: absent`, a
  passing `proxymind.fixed` test case). It never fails a run, and it is not reliable when the run did not finish. Remove
  those entries when you see them, so the file shows what is still open.

Accepting a finding means adding it to the baseline; making it count again means removing its entry. To start over,
write the file again.

### The fingerprint

A finding is identified by what it is and where, never by an id, a time or its evidence, so the same bug has the same
fingerprint in every run, project and pipeline:

```text
v1|<issue>|<METHOD>|<path>|<point>        fingerprint = first 32 hex characters of SHA-256 of that text
```

- `issue`: the issue library's id for the finding's class (`sqli`, `xss`, `idor`, `cors`, `exposure`, …).
- `METHOD`: the method of the request the finding is about, upper-case (empty if it has none).
- `path`: the URL path without scheme, host, query and fragment, repeated slashes collapsed, no trailing slash, and
  identifier segments folded into placeholders: numbers → `{id}`, UUIDs → `{uuid}`, long hex strings → `{hex}`,
  e-mail addresses → `{email}`, long random tokens → `{token}`. `/api/orders/1001` and `/api/orders/2002` are the same
  place. The host is not part of it, so a per-pull-request environment matches a baseline made on staging.
- `point`: the insertion point the scanner found it at, lower-case: `query q`, `form email`, `json user.name`,
  `path id`, `nested ctx.category (base64)`, `header user-agent`, `cookie session`, `request origin header`. Empty for findings
  about a whole operation (exposed files, authorization findings).

Status (suspected or proven) and severity are not part of it: a finding that a later run proves keeps its fingerprint.
Two findings with the same fingerprint count as one. Every baseline entry also stores the readable `key`. The
definition has a version (`fingerprint_version` in the file); a future change gets a new version, and this ProxyMind
refuses a baseline of a version it does not know instead of calling everything new.

What can still change a fingerprint: renaming a route or a parameter (that is a different place), a change in how the
scanner words an insertion point in a later ProxyMind release (rewrite the baseline after upgrading, and read the diff),
and an app that puts identifiers in its paths that are neither numbers, UUIDs, hex nor long tokens (`/users/jane`:
two users are two paths).

## Outputs

**Standard output** is a short summary: target, TLS state, requests sent, duration, findings by severity, proven versus
suspected, new/unchanged/fixed, each finding (`FAIL` marks those that fail the run), skips, why the run is incomplete,
and the exit code. Progress goes to standard error.

**SARIF 2.1.0** (`--sarif`) reuses the report writer (`proxymind report --format sarif`: rules with CWE and OWASP tags,
fix advice) and adds `partialFingerprints` with `proxymindFingerprint/v1` (the only partial fingerprint, so GitHub code
scanning matches alerts between runs), `baselineState` `new` / `unchanged` / `absent`, `level` by severity
(critical and high `error`, medium `warning`, otherwise `note`), and an `invocations` entry with `executionSuccessful`,
the exit code and notifications for each reason the run was incomplete or skipped. The location is the finding's URL
without its query. Evidence, request and response bodies, and target-supplied descriptions are not in the file.

**JUnit** (`--junit`): one test case per step of the run (`target reachable`, `login NAME`, `API description`,
`content discovery`, `crawl and scan`, `access control`, `automatic proving`: an `error` when the run could not finish
there, `skipped` when the rules skipped it), one per finding (`failure` when it fails the run), and a passing case per
baseline finding that is now gone.

**JSON** (`--json`, format `proxymind-ci-1`): the whole result: `target`, `profile`, `actor`, `requests`,
`tls_verified`, `complete`, `incomplete`, `skipped`, `checks`, `counts` (total, proven, suspected, new, unchanged, fixed,
failing, by severity), `findings` (each with fingerprint, key, issue, method, path, point, severity, status, title, url,
proof oracle and confidence, `state`, `fails`), `fixed` and `exit_code`.

## Credentials and identities

`--identity-file` takes a JSON file with one identity or a list, in the format of `proxymind identity set` (name, role,
`auth` cookies and headers, a `health` check, a `login` recipe). Any `${NAME}` in a string value is filled in from the
environment, so the file can be committed while the secrets come from the pipeline (`$$` is a literal `$`). A variable
that is not set is an error (exit 2) before anything is sent.

```json
{
  "name": "alice", "role": "user",
  "login": { "steps": [{
    "url": "https://staging.example.com",
    "request": "POST /api/login HTTP/1.1\r\nHost: staging.example.com\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n{\"username\":\"ci-alice\",\"password\":\"${CI_ALICE_PASSWORD}\"}",
    "token_json_pointer": "/token"
  }]},
  "health": { "url": "https://staging.example.com", "request": "GET /api/me HTTP/1.1\r\nHost: staging.example.com\r\n\r\n", "expect_status": 200 }
}
```

Use test accounts on the test environment. The first `--identity` scans; with two or more, each is crawled and the
access-control checks (IDOR, missing function-level checks, GraphQL object access) run between them. When a session
expires during the scan the identity logs in again; if that keeps failing the run stops with "session lost".

The values filled in from the environment, and cookie and header values in identity files, are removed from everything
the run prints or writes, in addition to the pattern-based redaction the reports use. Login recipes run as the CI actor
(so they need the tiers the login request needs: a POST is `active_intrusive`).

## Safety

- **Scope and rules first.** Out-of-scope targets are an error; every request of the run, the scanner's payloads
  included, is checked against the ROE one by one, with the DNS-rebinding check, rate limits and the audit log.
- **No approvals.** See "Rules of engagement for CI". CI cannot approve its own requests or anybody else's. Requests that
  needed approval leave pending entries in the project (visible with `proxymind approvals` when `--project` is used); they
  are never decided.
- **A project file is active content** (threat model F-2). A fresh in-memory project has nothing in it. With
  `--project`, the project's *data* (history, findings, identities, model) is used, but the run never starts the
  project's extra listeners, scan schedules or workflow triggers (those only start in `proxymind ui` and the desktop
  app, which `ci` is not), and for its duration the service ignores the settings that could steer it: saved network
  settings (upstream proxies, host overrides, client certificates), session-handling rules and macros, and the OAST
  callback settings. Identity login recipes run as `ci:pipeline` instead of the person who saved the identity. The ROE
  file given with `--roe` is used for the run only, and is not written into the project. `--project` also lets earlier
  findings in the file take part: the proving step re-checks every suspected finding in the project, not only this
  run's, and only findings created or touched during the run count in the results.
- **TLS verification is on** for the target (threat model F-12; the interactive proxy is the one that leaves it off).
  `--insecure` turns it off, prints a warning at the start and `TLS verification: OFF` in the summary, and sets
  `tls_verified: false` in the JSON. Use it only for staging hosts with self-signed certificates.
- **Hard caps.** `--max-requests N` counts every request the run sends and refuses the next one once N is reached;
  `--budget-minutes N` does the same by time and stops the scan. Either makes the run exit 2 when it cut off work
  (a cap that is reached when nothing is left to do is not an error). Without them there is no cap besides the profile's
  own limits (pages, operations, requests per operation); set both in a pipeline.
- **Target content is untrusted.** Anything that came from the target and is printed (titles, URLs) has control
  characters and escape sequences removed and is escaped in XML; secrets are redacted as in reports.
- **Stateful checks.** The scanner re-sends recorded submissions (`POST`/`PUT`) in a few checks, which changes data on
  the target like the original did. Use a test environment you can reset.
- **Chromium.** Crawling single-page apps and the XSS proofs need Chromium (`PROXYMIND_CHROMIUM=/path/to/chrome`). Without
  it reflected XSS stays *suspected*, so it does not fail a `--fail-on proven` run; the output says so.

## Not done yet

- OAST (blind SSRF, XXE, SQL injection by callback): a run has no callback listener, so those probes are skipped.
- Incremental scans of what changed in a pull request, and comments on the pull request: use the SARIF upload.
- The GitLab snippet writes SARIF as a job artifact; GitLab's security dashboards use their own report format.
- Cross-user checks use the identities' crawls only (no recorded browsing); for deeper coverage use the interactive
  tools, then `proxymind regress export` for what they prove.
