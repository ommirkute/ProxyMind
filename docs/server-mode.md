# Running a project server (accounts, sessions, TLS)

`proxymind ui` is for one person on one machine. `proxymind serve --accounts` is the same web UI and API for a small
team: people sign in with a password and an authenticator app, a browser holds a session instead of the install token,
and the server listens on a network address over TLS. The design is ADR-0022; this page is how to run it and what is
not finished.

**Not finished yet (read this first).** Every signed-in member of the served project acts as a human with full powers:
roles (owner, tester, viewer) are stored and shown, but `pm-service` does not enforce them until ADR-0022 step 6. Agent and
CI tokens (`pm3_`, `proxymind login`, the MCP bridge to a server) are step 5; the install token is refused in server mode
and nothing replaces it yet. The web UI has no pages for sign-in, setup or invites yet; until the UI task lands the
endpoints in the last section are used directly. Passkeys and OIDC are steps 7 and 8. Treat a server today as a preview
for testing the mechanics, not for a client engagement.

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

Invited people do the same through an invite (`POST /api/v1/auth/invites`, or the link
`https://pm.example.com/#invite=<token>`): choose a username and password, enrol an authenticator, sign in.

### Lost the owner

```bash
proxymind server reset-owner --server-home ~/.proxymind/server --public-url https://pm.example.com
```

Run on the server host as the user that owns the server home (write access to it is the same authority as the data). It ends
every session, voids older setup tokens, writes a `local_console` entry to the security log and prints a new setup URL that
creates a new owner (disable the old account afterwards). It works while the server runs.

## What the server enforces

- **Sessions:** a random 256-bit id in the cookie, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; `Secure` and named
  `__Host-pm_session` over TLS or behind a proxy, `pm_session` without `Secure` only on loopback plain HTTP. Only a hash is
  stored. Idle 8 hours, absolute 7 days. A new id at every sign-in; a cookie the client brings to the sign-in is never
  promoted. Signing in again while signed in ends the old session of that user (this is also how a person becomes "fresh").
- **Fresh sign-in (10 minutes)** for creating or revoking invites, disabling, enabling or resetting a user's second factor,
  enrolling or removing an authenticator, new recovery codes and changing the password. Without it: 403 with
  `"code": "fresh_login_required"`; sign in again and repeat.
- **CSRF:** every state-changing `/api/` request (the sign-in endpoints too) needs `X-ProxyMind: 1` and an `Origin` equal to the
  public origin, or no `Origin` and `Sec-Fetch-Site: same-origin`; anything else is 403. No CORS header is ever sent.
- **Membership:** a signed-in user may use the project's API only with a membership (any role) on the served project, else
  403 `not_a_member`. The project id is the random `project_id` stored inside the project file. A server admin without a
  membership keeps the account endpoints.
- **Sign-in:** one error text for a wrong password, unknown user, disabled user and wrong code; throttling per account and per
  client address with growing delays (429 with `Retry-After`; never a lock); the number of concurrent password hashes is capped.
- **Security log:** `pm-accounts` writes every sign-in, failure, logout, credential change, invite and administrator action to a
  chained log in `server.db`. No password, TOTP secret, session id or token is written to it, to the project's audit log, to
  the process log or into an error message (a test greps for them).
- **Not accepted in server mode:** the install token (`/auth?token=` is 404, `Authorization: Bearer` is 401).

## The auth endpoints (for the UI and scripts)

All under `/api/v1/auth`, JSON, described with their request and response types in `docs/api/openapi.json`. Every
state-changing call needs the CSRF headers above. Errors are `{"error": "<text>", "code": "<machine code>"}`.

| Endpoint | Session | What it does |
| --- | --- | --- |
| `GET /state` | no | `{server_mode, setup_required, setup_allowed}` |
| `POST /setup` `{setup_token, username, display_name?, password, next?}` | no | First owner; answers like `login` (`enrolment_required`). |
| `POST /login` `{username, password, next?}` | no | `{step, pending?, expires_at?, user?, recovery_codes?, next}` with `step` = `authenticated` (cookie set), `second_factor_required` or `enrolment_required`. |
| `POST /login/second-factor` `{pending, code, next?}` | no | TOTP code or recovery code (`ABCD-EFGH-IJKL-MNOP`); `authenticated` and the cookie. |
| `POST /login/enrol` `{pending}` | no | `{secret_base32, otpauth_uri}`, once. |
| `POST /login/enrol/confirm` `{pending, code, next?}` | no | Confirms, sets the cookie, returns `recovery_codes` once. |
| `POST /invite/accept` `{invite, username, display_name?, password, next?}` | no | Creates the account, continues like `login`. |
| `GET /me` | yes | `{user, actor, project_id, role, session, fresh}` |
| `POST /logout` | yes | Ends this session. |
| `GET /sessions`, `DELETE /sessions/{reference}`, `POST /sessions/revoke-all` `{keep_current?}` | yes | List, end one, "sign out everywhere". |
| `POST /password` `{current, new_password}` | fresh | Ends other sessions, renews this one. |
| `POST /totp/begin`, `POST /totp/confirm` `{code}`, `POST /totp/disable`, `POST /recovery-codes` | fresh | Authenticator and recovery codes. |
| `GET /users`, `POST /users/{id}/disable`, `/enable`, `/reset-second-factor` | admin (+fresh) | Account administration. |
| `GET /invites`, `POST /invites` `{role, ttl_hours?}`, `DELETE /invites/{id}` | admin or project owner (+fresh) | Invites; the token is returned once, with `url` = `<origin>/#invite=<token>`. |

`next` is a path on this server: it must start with exactly one `/`, hold only visible ASCII and no backslash, else the answer
says `/`.

In single-user mode these endpoints answer 404.

## Limits to know

- An event stream (`/events`) opened before a session is revoked keeps running until the client disconnects; step 6 filters
  events by membership and closes them.
- Roles are not enforced yet (see the top). Member management (changing a role) is not an endpoint yet.
- Step-up is "sign in again"; there is no password-only re-check endpoint.
- The server's audit checkpoints (signed, hourly) are not scheduled yet.
