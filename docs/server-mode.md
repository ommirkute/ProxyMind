# Running a project server (accounts, sessions, TLS)

`proxymind ui` is for one person on one machine. `proxymind serve --accounts` is the same web UI and API for a small
team: people sign in with a passkey, or a password and an authenticator app, a browser holds a session instead of the install token,
and the server listens on a network address over TLS. The design is ADR-0022; this page is how to run it and what is
not finished.

**What is finished.** Roles are enforced (ADR-0022 step 6): owner, tester and viewer decide what a person, and what each of
their tokens, may do ("Roles and members" below), and passkeys work ("Passkeys" below, step 7). **Not finished:** OIDC (step 8), the per-host binding
of secret placeholders (a placeholder is per user now, but still unredacts toward any in-scope host), and the server's signed
checkpoint schedule. Run it for a small team you trust with the project's data; the security review of step 9 is still to come.

## What you need

- A project file with rules of engagement (`proxymind roe use roe.yaml`), as for `ui`.
- A **server home**, a folder only the server's user can read (default `~/.proxymind/server`, or `--server-home DIR`):
  `server.db` (accounts, hashes, sessions, the security log) and `server.key` (32 random bytes, mode 0600; the server
  refuses to start if other users can read it). **Back up `server.key` separately from `server.db`**: the database is
  useless without it, and with both a thief gets the encrypted TOTP secrets. Never put either in the project file.
- Accounts are separate from the project: handing a `.pmproj` to a client carries no password hash or session.

## Starting it

The server refuses to start rather than listen beyond loopback in plain HTTP. Pick one.

**1. Your own certificate (recommended for a team).** certbot, Caddy's store or a corporate CA:

```bash
proxymind serve --accounts --project client.pmproj \
  --listen 0.0.0.0:443 --public-url https://pm.example.com \
  --tls-cert /etc/letsencrypt/live/pm.example.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/pm.example.com/privkey.pem
```

The files are looked at every few seconds when someone connects and reloaded when their modification time or size
changes, so a renewal needs no restart. A new pair that does not parse or does not match is logged as a warning and the old
certificate stays in use. HSTS (`Strict-Transport-Security`) is sent.

**2. Behind a reverse proxy** (Caddy, nginx, Traefik terminate TLS):

```bash
proxymind serve --accounts --project client.pmproj \
  --listen 127.0.0.1:7777 --public-url https://pm.example.com \
  --behind-proxy --trusted-proxy 127.0.0.1
```

The server then listens on loopback or a private address only, never on `0.0.0.0` or a public one. It believes
`X-Forwarded-Proto` and `X-Forwarded-For` **only from the addresses in `--trusted-proxy`** (repeat it for each proxy); any
other peer is treated as a direct client. Cookies are the `Secure` `__Host-` kind, and the proxy must pass the original
`Host` header (`proxy_set_header Host $host;` in nginx) and set `X-Forwarded-Proto https` and `X-Forwarded-For`. The
client address in the security log is the first address from the right of `X-Forwarded-For` that is not a trusted proxy.

**3. Self-signed with a pinned key** (a lab, one tester's server, agents on a trusted network):

```bash
proxymind serve --accounts --project client.pmproj \
  --listen 0.0.0.0:8443 --public-url https://10.0.0.5:8443 --tls-self-signed
```

On first start it makes a P-256 key and a one-year certificate in the server home (`server-tls.key.pem`, mode 0600, and
`server-tls.crt.pem`) with the host names and addresses from `--public-url`, `--allowed-host` and the listen address as
subject alternative names, and prints the **pin**: `sha256:` and the base64 SHA-256 of the certificate's public key
(`sha256:<44 characters>`; the same value in hex is accepted wherever a pin is read). The same key is reused at every
start, so the pin stays the same; the certificate is made again, with the same key, when it has under 30 days left or
the names changed. A new key (the key file was deleted) is a new pin, and the server says so. Clients that pin the
server (`pm_tls::server::pin_client_config`, used by `proxymind login` once step 5 lands) accept exactly that key and
fail on any other, with both pins in the error. A browser needs you to accept the certificate once; that is why this is
the lab option. HSTS is not sent for a self-signed certificate.

The certificate of the server is never issued by, or related to, the interception CA, whose key stays on the tester's machine.

### Other options

| Option | Meaning |
| --- | --- |
| `--listen ADDR` | Default `127.0.0.1:7777`. Loopback with no TLS flag is plain HTTP (for a first look); the cookie is `pm_session` without `Secure`. |
| `--public-url URL` | The address people type, no path. Browsers must send an `Origin` equal to it on every state-changing request. Required beyond loopback and behind a proxy; with plain loopback the loopback names and the port are used. |
| `--allowed-host H` | Another `Host` name to answer to (repeatable). Anything else gets 403 (DNS-rebinding defence). |
| `--server-home DIR` | Default `<home>/server`; also `PROXYMIND_SERVER_HOME`. |
| `--proxy ADDR` | Also run the interception proxy here. **Off by default**: the CA key belongs on the tester's machine. |

`serve` starts the same things `ui` does around the service (plugins, scheduler, workflow triggers, notifications, the
file watchers) and keys the project's audit chain with a key derived from `server.key`.

## First start: the owner

A server whose `server.db` has no owner answers only `GET /api/v1/auth/state` and `POST /api/v1/auth/setup`; everything
else is 503 with `"code": "setup_required"`. It prints once per start:

```
This server has no owner yet. Open this URL within the hour to create one (it works once):
  https://pm.example.com/#setup=pmset_...
```

The token is 128 random bits, stored only as an HMAC, valid for one hour and one use. It is in the URL's **fragment**, which
browsers never send to a server. Setup is served only over TLS (or behind a trusted proxy that says HTTPS) or, on plain
loopback, to a peer on the same machine; otherwise the setup endpoint answers 403. Setup creates the account (password of
at least 12 characters), makes it **server admin and owner of the served project**, and goes straight into TOTP
enrolment: there is no session until an authenticator is confirmed. The recovery codes shown at that moment are shown once.
**Or with a passkey instead** (recommended, see "Passkeys"): the setup page asks for a username and a passkey, creates an
owner with no password at all, and signs in; nothing is made and the setup token is not used until the passkey registers.

In the browser, open that URL: the web UI shows the setup screen (see "The web UI" below). Invited people do the same through an invite (`POST /api/v1/auth/invites`, or the link
`https://pm.example.com/#invite=<token>`): choose a username and password, enrol an authenticator, sign in.

### Lost the owner

```bash
proxymind server reset-owner --server-home ~/.proxymind/server --public-url https://pm.example.com
```

Run on the server host as the user that owns the server home (write access to it is the same authority as the data). It ends
every session, voids older setup tokens, writes a `local_console` entry to the security log and prints a new setup URL that
creates a new owner, with a password and authenticator or with a passkey (disable the old account afterwards). It works
while the server runs.

## What the server enforces

- **Sessions:** a random 256-bit id in the cookie, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; `Secure` and named
  `__Host-pm_session` over TLS or behind a proxy, `pm_session` without `Secure` only on loopback plain HTTP. Only a hash is
  stored. Idle 8 hours, absolute 7 days. A new id at every sign-in; a cookie the client brings to the sign-in is never
  promoted. Signing in again while signed in ends the old session of that user (this is also how a person becomes "fresh").
- **Fresh sign-in (10 minutes)** for creating or revoking invites, disabling, enabling or resetting a user's second factor,
  enrolling or removing an authenticator, new recovery codes and changing the password. Without it: 403 with
  `"code": "fresh_login_required"`; sign in again and repeat.
- **CSRF:** every state-changing `/api/` request (the sign-in endpoints too) needs `X-ProxyMind: 1` and an `Origin` equal to the
  public origin, or no `Origin` and `Sec-Fetch-Site: same-origin`; anything else is 403. No CORS header is ever sent. The one
  exception is a request that carries a `pm3_` bearer token and **no session cookie**: it has no ambient credential for a
  page to ride on, so it needs neither (curl, CI jobs and the MCP bridge send neither). With the session cookie present the
  checks apply in full, whatever else the request carries.
- **Membership:** a signed-in user may use the project's API only with a membership (any role) on the served project, else
  403 `not_a_member`. The project id is the random `project_id` stored inside the project file. A server admin without a
  membership keeps the account endpoints.
- **Sign-in:** one error text for a wrong password, unknown user, disabled user and wrong code; throttling per account and per
  client address with growing delays (429 with `Retry-After`; never a lock); the number of concurrent password hashes is capped.
- **Security log:** `pm-accounts` writes every sign-in, failure, logout, credential change, invite and administrator action to a
  chained log in `server.db`. No password, TOTP secret, session id or token is written to it, to the project's audit log, to
  the process log or into an error message (a test greps for them).
- **Not accepted in server mode:** the install token (`/auth?token=` is 404, `Authorization: Bearer <install token>` is 401).
  What replaces it for scripts, CI and agents is a `pm3_` token (next section).

## Passkeys

A **passkey** (WebAuthn) is the recommended way in: the browser asks the person's device (fingerprint, face, PIN, a
security key, a phone) to sign a challenge for this server, so there is no shared secret to phish or leak. User
verification is always required, so a passkey sign-in is **a complete sign-in on its own** and counts as the owner's required
second factor. Password plus authenticator app stays as the fallback for devices without passkeys; both are allowed from the
start, and an owner can **require** passkeys (below). ADR-0022 step 7 has the design.

- **Add one:** Account → Passkeys → "Add a passkey" (a name is optional; it asks for a fresh sign-in). Add one per device; at
  most ten per account. List, rename and remove are on the same panel. Removing one ends your other sessions.
- **Sign in:** the sign-in page has "Sign in with a passkey". With no username typed, the browser offers the passkeys it holds
  for this server (usernameless); the re-authentication dialog uses the signed-in account's own.
- **Setup and invites** offer a passkey (recommended) or a password; with a passkey the account has no password.
- **The host name is the RP id.** A passkey belongs to the server's host name, the host of `--public-url` (`pm.example.com`), never
  an IP address: a server whose public URL is an IP address has no passkeys, and the sign-in page says so. A loopback-only
  server started without `--public-url` offers `localhost`, so a first look works at `http://localhost:7777` but not at
  `http://127.0.0.1:7777`. The page must be at that host name (or below it) to add or use a passkey. **Renaming the server
  invalidates every passkey.** Plan the name before people enrol, or keep an owner with a password and an authenticator so the
  server can be re-enrolled, and issue enrolment links (below) after a rename.
- **What the server checks** (`clientDataJSON` type, the single-use five-minute challenge bound to who asked, the exact origin,
  the RP id hash, user presence and verification, the signature; ES256, EdDSA and RS256 only; attestation is not requested and not
  verified) is in ADR-0022's step 7 note. The signature **counter** must grow: if it does not (and either count is non-zero) the
  sign-in is refused like any failure and the security log says `passkey_clone_suspected`; authenticators that always report zero
  are fine.
- **Throttling and audit** are the password sign-in's: the same account and address counters, one `invalid credentials` answer for
  every refusal, every success and failure in the security log (a credential id, key or signature is never written).
- **Usernames are not revealed.** The options for a name that has no passkey (unknown, disabled, or none enrolled) list stable
  decoy credential ids, so asking does not tell. (An account with more than three passkeys shows a count a decoy does not.)
- **Require a passkey** (Users & invites → "Passkeys on this server"; server administrators, fresh sign-in, audited; you need a passkey
  yourself first). The rule: **every account must have a passkey.** An account without one can still sign in with its password
  and authenticator, but only to add one: the session is *restricted*, the server answers 403 `passkey_enrolment_required` to
  everything except who-am-I, sign-out and the passkey endpoints, and the app shows only "Add a passkey to continue". An account
  with a passkey **cannot sign in with a password** (403 `passkey_required` after the right password, so a phished password
  gets no session) and cannot remove its last passkey. Recovery codes are part of the password route, so they stop working for
  such an account too. `pm3_` tokens are machine credentials and are not affected.
- **Without the rule,** an account that has a passkey and no authenticator also cannot finish a password sign-in (a password alone is never
  enough, and a password holder is not offered to enrol an authenticator); one that has both may use either. An authenticator
  can be turned off by an account that has a passkey.
- **The owner always needs a second factor.** A passkey is one; so is an authenticator. Removing the last one of an owner or
  administrator who has a password is refused (409 `second_factor_required`), as is removing the last passkey of a passkey-only account (409 `last_passkey`).
- **Recovery.** Recovery codes work for accounts that have a password and authenticator. Someone who lost every way in, a passkey-only
  user who lost their device included, is recovered by an **enrolment link**: an owner (Members → "Recovery link", for a tester or
  viewer; an administrator, in Users, for anyone else) makes a one-time link `…/#enrol=<token>` that lives an hour and works once
  (a fresh sign-in is needed; the link is shown once). **Making it ends the person's sessions and revokes their tokens; using it replaces how
  they sign in**: their passkeys, password, authenticator and recovery codes are removed and they register a new passkey (signed
  in at once) or choose a new password (then enrol an authenticator). A project owner cannot issue one for a peer owner or an
  administrator, nor for themselves. If the last owner is locked out, `proxymind server reset-owner` (above) prints a setup URL for a new
  owner, who can enrol a passkey.
- **Browsers.** Passkeys need a secure context: HTTPS, or `localhost`. Chromium, Firefox and Safari work; an authenticator that cannot do
  user verification (a security key with no PIN set) is refused with a message.

## Roles and members

A member has one role on the project. The whole table is `docs/access.md`; the effect of it on every route and tool is
`docs/access-matrix.md` (generated, and a test fails when it drifts).

| | owner | tester | viewer |
| --- | --- | --- | --- |
| Read history, findings, reports, model, coverage | yes | yes | yes, **with secrets replaced by placeholders**, as agents see them |
| Send traffic (replay, fuzz, scan, crawl, workflows, proofs) through the gate | yes | yes | no |
| Write findings, hypotheses, notes, identities, workflows, schedules, checks | yes | yes | no |
| Decide approvals | any | only what their own tokens (or they) asked; with `approvals.testers_decide_team: true` also other testers' tokens | none |
| ROE, scope, network, listeners, integrations, model keys and settings, trust, updates | yes | no | no |
| Members and roles, other people's tokens | yes | no | no |

- **Agents and tokens.** A token is its own actor with the lower of its ceiling and its owner's current role, and never above
  `tester`: an owner's token cannot approve, change the ROE or manage members. The people-only rules (approve, ROE, rules,
  listeners, keys, workflow triggers, plugins, schedules) hold whatever the role.
- **Deny by default.** An actor the server did not register on a request is a viewer. Every public service method that
  takes an actor asks for its permission first; the API checks the route's permission before the handler and the MCP
  endpoint the tool's.
- **Takes effect on the next request.** The role is read from `server.db` on every request. A demotion or removal ends the
  member's sessions; their tokens follow the new role at once (removal revokes them). A promotion shows at the next
  request, with no new sign-in. An open event stream checks its session or token every two seconds and ends when it no
  longer holds; its topics follow the role (a viewer gets no intercept, approvals, audit, plugin or Collaborator events).
- **Members** (owners; a fresh sign-in for changes): `GET /api/v1/auth/members`, `PUT /api/v1/auth/members/{user_id}` with
  `{"role": "owner|tester|viewer"}`, `DELETE /api/v1/auth/members/{user_id}`; the **Members** panel on Account, Users & invites.
  The last owner cannot be demoted or removed. Invites still make new accounts.
- **Four eyes.** `approvals: { require_other_person: true }` in the ROE: an owner cannot decide an approval that they or
  their own tokens asked, so a different owner must. `testers_decide_team: true` lets a tester also decide approvals asked by
  other testers' tokens. Both default to false. Approvals record who asked (account, token, role).
- **The audit log** names the account, the session or token and the address of every action made over the API or MCP
  (version 2 records). Work a request starts (scan tasks, fuzzer attacks) runs after the request: its records name the
  account and token, and the session and address last seen for that actor.
- **The web UI** hides what a viewer cannot do (sidebar entries and buttons) and reads its role again when the event stream says it changed (or the tab is shown again), so a
  promotion shows without signing in again; the server is the authority.

## The web UI

The same web UI as single-user mode, with a few screens in front of it. When it loads it asks `GET /api/v1/auth/state`; in
single-user mode that does not answer 200 and nothing changes (no extra screen, no extra navigation entry).

- **Setup** (`/#setup=<token>`): choose username, display name and password, then add an authenticator (QR code, or
  type the secret, then a code), then save the ten recovery codes, which are shown once with copy and download. The
  token is taken out of the address bar as soon as it is read. Without the token the page says the link is printed on
  the server console (and lets you paste it); where setup is not served (no TLS and not the server's own machine) it says so.
- **Sign-in:** "Sign in with a passkey" (usernameless), or username and password, then the code from the authenticator app, or "Use a recovery code". An account without
  an authenticator goes through the enrolment first. A wrong password, unknown user and wrong code all show the same
  text; a throttled attempt shows the server's message with the wait.
- **Invite** (`/#invite=<token>`): choose username and display name, then a passkey (recommended) or a password (then the same
  enrolment and recovery codes).
- **Enrolment link** (`/#enrol=<token>`): says whose account it recovers and that it replaces how they sign in; then a new passkey or
  a new password. The token is taken out of the address bar.
- **Add a passkey to continue:** what an account without a passkey sees after signing in while passkeys are required.
- **Session lost:** when the server answers 401 (session expired, signed out elsewhere, password changed) the app is
  replaced by the sign-in with "Your session ended", and after signing in you are back on the page you were on.
- **Fresh sign-in:** actions that need one (invites, users, password, authenticator, recovery codes) open a "Confirm it's
  you" dialog (password, then code); the action is then repeated once. Cancelling leaves it undone.
- **Not a member:** a signed-in account with no role in the served project gets a screen saying so, with a sign-out button.
- **Account** (navigation entry "Account", server mode only): who you are (user, actor, role, project), your sessions
  (this one is marked; sign one out, or sign out everywhere else), passkeys (add, rename, remove), change password, set up a new authenticator or turn it
  off (some accounts must keep one), new recovery codes, sign out.
- **Users & invites** (server administrators and project owners): "Passkeys on this server" (the require rule; administrators), members
  with roles and a recovery link (owners), users with disable, enable, reset second factor and a recovery link (administrators);
  invites with role and expiry, the link shown once with a copy button, the list and revoke.

Nothing secret is written to browser storage or the console. `next` is followed only if it is a path on this origin.
`POST /auth/login/enrol` and `POST /auth/totp/begin` also return `qr_svg`, the authenticator URI as an SVG QR code (the UI
has no QR library).

## The auth endpoints (for the UI and scripts)

All under `/api/v1/auth`, JSON, described with their request and response types in `docs/api/openapi.json`. Every
state-changing call needs the CSRF headers above. Errors are `{"error": "<text>", "code": "<machine code>"}`.

| Endpoint | Session | What it does |
| --- | --- | --- |
| `GET /state` | no | `{server_mode, setup_required, setup_allowed, passkey_supported, passkey_rp_id, passkey_note, passkey_required, passkey_count?}` (`passkey_count` only with a live session cookie) |
| `POST /setup` `{setup_token, username, display_name?, password, next?}` | no | First owner; answers like `login` (`enrolment_required`). |
| `POST /login` `{username, password, next?}` | no | `{step, pending?, expires_at?, user?, recovery_codes?, next}` with `step` = `authenticated` (cookie set), `second_factor_required` or `enrolment_required`. |
| `POST /login/second-factor` `{pending, code, next?}` | no | TOTP code or recovery code (`ABCD-EFGH-IJKL-MNOP`); `authenticated` and the cookie. |
| `POST /login/enrol` `{pending}` | no | `{secret_base32, otpauth_uri, qr_svg}`, once. |
| `POST /login/enrol/confirm` `{pending, code, next?}` | no | Confirms, sets the cookie, returns `recovery_codes` once. |
| `POST /invite/accept` `{invite, username, display_name?, password, next?}` | no | Creates the account, continues like `login`. |
| `GET /me` | yes | `{user, actor, project_id, role, session, fresh, passkey_count, passkey_enrolment_required}` |
| `POST /logout` | yes | Ends this session. |
| `GET /sessions`, `DELETE /sessions/{reference}`, `POST /sessions/revoke-all` `{keep_current?}` | yes | List, end one, "sign out everywhere". |
| `POST /password` `{current, new_password}` | fresh | Ends other sessions, renews this one. |
| `POST /totp/begin`, `POST /totp/confirm` `{code}`, `POST /totp/disable`, `POST /recovery-codes` | fresh | Authenticator and recovery codes. |
| `GET /users`, `POST /users/{id}/disable`, `/enable`, `/reset-second-factor` | admin (+fresh) | Account administration. |
| `GET /invites`, `POST /invites` `{role, ttl_hours?}`, `DELETE /invites/{id}` | admin or project owner (+fresh) | Invites; the token is returned once, with `url` = `<origin>/#invite=<token>`. |
| `POST /passkey/login/options` `{username?}`, `POST /passkey/login` `{response, next?}` | no | Sign in with a passkey (options, then the assertion); sets the cookie. |
| `POST /setup/passkey/options` `{setup_token, username, display_name?}`, `POST /setup/passkey` `{name?, response, next?}` | no | First owner with a passkey (no password); signs in. |
| `POST /invite/passkey/options` `{invite, username, display_name?}`, `POST /invite/passkey` `{name?, response, next?}` | no | Accept an invite with a passkey; signs in. |
| `POST /enrol-link/info` `{token}`, `POST /enrol-link/passkey/options` `{token}`, `POST /enrol-link/passkey` `{name?, response, next?}`, `POST /enrol-link/password` `{token, new_password, next?}` | no | Redeem a one-time enrolment link: whom it is for, a new passkey (signs in) or a new password (`enrolment_required`). |
| `GET /passkeys`; `POST /passkeys/options`, `POST /passkeys` `{name?, response}`; `PUT /passkeys/{id}` `{name}`; `DELETE /passkeys/{id}` | yes (adding and removing: fresh) | List (no key material), add, rename and remove the signed-in account's passkeys. Adding and removing give the session a new id; removing ends the other sessions. |
| `PUT /settings/passkey-required` `{required}` | admin (+fresh) | Require a passkey of every account, or stop. |
| `POST /users/{id}/enrolment-link` | admin or project owner (+fresh) | A one-time recovery link (an hour); ends the person's sessions and revokes their tokens. The token is returned once, with `url` = `<origin>/#enrol=<token>`. |

`next` is a path on this server: it must start with exactly one `/`, hold only visible ASCII and no backslash, else the answer
says `/`.

In single-user mode these endpoints answer 404, except `GET /state`, which answers `{"server_mode": false, …}` so the UI
knows which mode it is in.

## Tokens, login and the MCP bridge

Agents, CI jobs and plugins use **`pm3_` tokens**, one credential per actor, owned by a person. A token is
`pm3_<kind>_<64 hex digits>` with kind `agent`, `ci` or `plugin`; the `pm3_` prefix lets secret scanners find a leak. It is
shown once when it is made; the server stores only an HMAC-SHA256 of it under a key derived from `server.key`. A token carries:

- its **owner** (an account) and the project; it works only while the owner is an active member, so disabling, removing or
  (for what it may do) demoting the owner takes effect at its next request;
- an **actor**: requests with it are `agent:<name>`, `ci:<name>` or `plugin:<name>`, never anything the client sends. A name
  is unique among live tokens of its kind;
- a **role ceiling**, `tester` (default) or `viewer`, never `owner`: the token acts with the lower of this and its owner's
  current role. Enforced now: a *viewer* (either way) may only read on the REST API (`403 read_only_token`), may list tools
  but not call them over MCP, and is held to tier `passive`, which sends nothing. The finer role rules come with step 6;
- an optional **tier cap** (`read`, `passive`, `active_safe`, `active_intrusive`): the policy gate refuses anything above it,
  before scope and the rules, also for approved actions; the rules of engagement can only narrow it further;
- an **expiry** (default 30 days, 1 hour to 365 days in the UI and API, 1 minute to 365 days on the command line), a last-use
  time and use count (written at most once a minute) and revocation.

**Making tokens.** In the web UI: Account → API tokens (create with kind, name, role, highest tier and expiry; the value is
shown once with a copy button; the list shows last use and a Revoke button). Owners can list everyone's (`Everyone's
tokens`) and make a token for another member (`For user`), which asks for a fresh sign-in; one's own need none. Through the
API: `POST /api/v1/tokens` `{kind, name, role?, tier_cap?, expires_days?, for_user?}` answers with the token once;
`GET /api/v1/tokens[?all=true]`; `DELETE /api/v1/tokens/{id}`. A token **cannot** create, list or revoke tokens, or use the
`/auth` endpoints; a viewer cannot manage tokens. On the server host, with write access to the server home:

```bash
proxymind token create --server-home ~/.proxymind/server --user alice --kind agent --name claude \
    --role tester --tier-cap active_safe --expires 30d        # prints the token, once, on stdout
proxymind token list   --server-home ~/.proxymind/server --user alice     # --all for everyone's
proxymind token revoke --server-home ~/.proxymind/server t_0123456789abcdef
```

(The security log records `local_console` as the actor of those.) Away from the host, use the UI or the API.

**Using a token.** `Authorization: Bearer pm3_…`, and nowhere else (not a query string, not a cookie):

```bash
curl -H "Authorization: Bearer $PROXYMIND_TOKEN" https://pm.example.com/api/v1/status      # {"you_are": "agent:claude", …}
```

`proxymind login` checks a server and saves what is needed to use it:

```bash
proxymind login https://pm.example.com --token-env PROXYMIND_TOKEN             # certificate from a public CA
proxymind login https://10.0.0.5:7777 --pin sha256:…                           # self-signed: the pin the server printed
```

It asks for the token without echo (or reads `--token-env VAR`, or one line of stdin when there is no terminal) and writes
`<home>/servers.json` (mode 0600) with the address, the pin and the token only after `GET /api/v1/status` has answered for
that token over a verified connection. Without `--pin` the certificate must verify against the public roots built into
ProxyMind (a private CA needs `--pin`); with it the server's public key must hash to the pin, whatever its name or dates say.
A wrong pin fails with both pins named, is never retried with weaker checks and saves nothing. Run again without `--pin` it
keeps using the saved pin; `proxymind logout URL` forgets a server. `http://` works for loopback addresses only.

**MCP for agents.** `POST /api/v1/mcp` takes one JSON-RPC message (or a batch) and runs the same tools as `proxymind mcp`
under the token's actor, through the same service and gate: scope, tiers, approvals, redaction and untrusted-content tagging
are unchanged, and an agent's pending approvals are decided by people in the UI or `proxymind approvals`. The bridge makes it a
stdio server for any MCP client:

```bash
proxymind mcp --server https://pm.example.com                      # uses the pin and token `proxymind login` saved
proxymind mcp --server https://pm.example.com --token-env PROXYMIND_TOKEN
claude mcp add proxymind -- proxymind mcp --server https://pm.example.com
```

It checks the server and the token first and exits with the reason on a bad certificate, a wrong pin or a refused token; later
a revoked token turns each call into a JSON-RPC error, and a certificate or pin failure ends the bridge. The actor is the
token's: `--actor` means nothing here.

## Limits to know

- A viewer's token reads on REST (GET only) and calls the read tools of the MCP endpoint; everything else is refused.
- A tier cap is kept for the actor id until another token of that name sets another, also after the token is revoked.

- Placeholders of secrets are per user now, but a placeholder is not bound to the host its secret came from: an agent or tester
  can still send it to any in-scope host (threat model F-5, left for the security review).
- REST reads by an agent token of routes without an actor (findings, the model) are not redacted; a viewer's are.
- Export, delete and seal of the project are file operations, not service methods yet (3.3); "viewers comment" waits for 3.4.
- Step-up is "sign in again" (with a passkey or a password and code); there is no password-only re-check endpoint.
- Passkeys: attestation is not requested or verified, there is no browser autofill for the username field, and unused enrolment links
  cannot be listed or revoked (a newer one replaces them; they expire in an hour).
- The server's audit checkpoints (signed, hourly) are not scheduled yet.
