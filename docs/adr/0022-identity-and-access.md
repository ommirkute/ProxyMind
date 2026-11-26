# ADR-0022: Identity and access: accounts, sessions, tokens and roles for the project server

**Status:** Accepted (2026-11-21, owner decision; roadmap work packages 3.1 and 3.2). The owner chose the recommended
answers to the open questions below: both identity sources with local accounts first, redacted views for viewers,
invite-only joining, and step 0 (F-1 documentation, F-2 safe open) now; the other questions take their
recommendations. The threat model is
`docs/threat-model.md`; finding and boundary ids (F-1, B2.3…) below refer to it.

## Context
Today ProxyMind has one user. The API acts as `human:$USER`, fixed when the process starts; whoever holds
`~/.proxymind/api-token` is that human (`pm-api/src/lib.rs`, `AppState.actor`). The token is also the cookie value, lasts
30 days, and cannot be revoked short of deleting the file. MCP clients choose their identity with `--actor` and present
no credential. About 53 checks of the form `actor.kind != Human` in `pm-service` decide what agents may not do; there is
no table of them and no notion of a role.

Phase 3 changes that: several people on one project server, over a network, each with a role (3.2), agents and CI
acting on their behalf (3.7), integrations holding third-party tokens (3.5) and an Internet-facing callback server (3.6).
The threat model lists what that adds. This ADR decides the identity half: who a request is from, how that is proved,
what they may do, how it is recorded, and how the server is reached safely. The project server's data model (3.3) and
shared work (3.4) are separate decisions that build on this one.

Constraints from existing decisions:
- **ADR-0005:** `pm-service` is the only place actions happen; every call carries an actor and passes the gate. Roles
  must be enforced there, not in `pm-api`, or MCP, the CLI and the UI could route around them.
- **ADR-0004 and ADR-0013:** a project is a single file that is copied, handed to clients and sealed. Accounts must not
  live inside it.
- **ADR-0003:** TLS is rustls with ring. A dependency that drags in OpenSSL needs a good reason.
- **Roadmap decision:** every feature stays open source, team features included. Nothing here may need a paid service.
- **Naming:** `pm-identity` already means a *test* identity (cookies and headers the tester sends as another user of the
  target). Accounts of ProxyMind's own users are called **accounts** and live in a new crate, `pm-accounts`. The UI and
  docs must not call both "identity".

## Decision

### Modes
- **Single-user mode is the default and does not change.** `proxymind ui`, the desktop app, `proxymind mcp --actor …`
  and the install token behave exactly as today: no accounts, no `server.db`, loopback only, the actor is
  `human:$USER`. In code this is the **implicit owner** principal: every authorization check passes, so the existing
  test suite is the proof that nothing changed.
- **Multi-user is opt-in** and exists only when running the project server (working name `proxymind serve --accounts`,
  3.3). It needs a server home with its own database, TLS if it listens beyond loopback, and a first owner.
- The two modes share the service layer and the policy gate. They differ in how a request becomes a `Principal`.

### Identity sources: local accounts first, OIDC second, both in Phase 3
- **Local accounts** are the base. A self-hosted server for a small testing team often has no identity provider, and the
  owner may not run one. They are also the break-glass path when an identity provider is down or compromised.
  - **Passkeys (WebAuthn) are the recommended primary factor**: phishing-resistant, no shared secret on the server.
    User verification is required. Relying-party id is the server's host name (documented: changing the host name
    invalidates passkeys; plan one before enrolling).
  - **Password plus TOTP is the fallback** for devices without passkeys and for headless setups. Both are allowed
    from day one; the owner can set "require a passkey" per server. The owner role always requires a second factor
    (passkey, or password plus TOTP).
  - A password alone is never enough to sign in to a role that can send traffic. Accounts with only a password can
    exist (a viewer, if the owner allows it); this is a setting, off by default.
- **OIDC** (generic, any compliant provider: Keycloak, Entra ID, Okta, Google, GitLab, Authentik) is the second source,
  added after the session machinery works. Authorization code flow with **PKCE (S256)**, discovery from the issuer URL,
  the ID token verified with the provider's JWKS (RS256 and ES256 through ring).
  - **What identifies a user:** the pair `(iss, sub)`. Never the email. The owner configures one issuer per provider and
    the server refuses a token whose `iss` is not exactly that string (and checks the `iss` response parameter, RFC
    9207, to stop mix-up attacks), `aud` contains the client id, `exp`, `iat` and the `nonce` it stored for this login.
    `redirect_uri` is fixed and compared exactly.
  - **Claims used:** `sub` and `iss` (identity), `email` and `name` (display only; shown in the UI, not used for
    authorization), `email_verified` (needed to link an existing local account by email, and linking is off by default,
    owner-enabled and shown in the audit log), and optionally one configurable group claim mapped to a project role.
  - **Provisioning:** off by default; people join by invite. The owner may enable auto-create for listed email domains,
    and a new account then gets `viewer` at most. A claim can grant `tester` or `viewer` on a project; **it can never
    grant `owner` or server admin**: those are granted only by an existing owner. A compromised provider therefore
    cannot make itself owner.
  - Local MFA is not asked of OIDC users; the provider's assurance is used, and an optional `acr` or `amr` requirement
    can be set per provider.
  - Not in scope: SAML (use an OIDC bridge), SCIM, back-channel logout.
- **If the owner chooses only one:** local accounts alone are enough to ship 3.1 and 3.2. OIDC alone is not
  recommended: a lone tester or small firm would need an identity provider to use the server at all, and a provider
  outage would lock everyone out.

### Sessions (browser)
- **Server-side sessions.** After login the server creates a random 256-bit session id, stores only its SHA-256
  (`sessions` table: user, created, last seen, idle and absolute expiry, auth method, client address and user agent
  as hints) and sets it as a cookie. No JWT for sessions: they could not be revoked.
- **Cookie:** `__Host-pm_session` when served over TLS (`Secure`, `Path=/`, no `Domain`); `pm_session` without `Secure` only
  on loopback plain HTTP; always `HttpOnly` and `SameSite=Strict`. The login flow's own short-lived state cookie (OIDC
  `state`, nonce, PKCE verifier; 10 minutes) is `SameSite=Lax` so the redirect back from the provider carries it.
- **Lifetime:** idle 8 hours, absolute 7 days (both owner-configurable, with upper bounds). The single-user cookie is
  unchanged.
- **Rotation:** a new id at login, after step-up (re-authentication for sensitive actions), and when a user's role or
  credentials change. A pre-login id is never promoted (no fixation).
- **Revocation:** deleting the row ends the session at the next request. Users see their sessions and can sign out
  everywhere; owners can end any user's sessions; changing a password or removing a passkey or TOTP ends all other
  sessions; removing or demoting a user ends theirs and their tokens.
- **Sensitive actions need a fresh login** (within 10 minutes): changing roles, creating or revoking tokens for other
  users, editing the ROE, configuring OIDC or integrations, enrolling or removing a credential.
- **CSRF defence, in layers:** `SameSite=Strict` on the session cookie; every state-changing request must carry
  `X-ProxyMind: 1` (as today), which a cross-site form cannot send and a cross-origin script cannot send without a
  preflight the server refuses; and mutating requests must have an `Origin` (or `Sec-Fetch-Site: same-origin`)
  matching the server's configured public origin, else 403. No CORS headers are ever served. Clients that use bearer
  tokens send no cookies, so CSRF does not apply to them. A test walks the route table: every non-GET route is covered,
  and no GET route may change state.
- **Hosts:** the `host_is_local` check generalises to an `allowed_hosts` list set at start (the server's public names).
  In single-user mode it stays loopback names only, which keeps the DNS-rebinding defence of today.
- **Login hardening:** per-account and per-address throttling with exponential back-off (not a hard lock, which would
  let anyone lock an owner out), a dummy hash for unknown users so timing and messages do not reveal whether an account
  exists, constant error text, a semaphore limiting concurrent Argon2 hashes, and audit of every success, failure,
  logout, credential change and token use.
- **`next=` after login** must be a relative path on the same origin.

### Machine credentials: the install token, agent, CI and plugin tokens
- **The install token continues, but only in single-user mode.** In multi-user mode it is not accepted for API calls.
  Its only role there is as a **setup token** printed on first start to claim the first owner (see bootstrap).
- **Tokens are credentials of a user, not of a machine.** `proxymind token create --kind agent|ci|plugin --name claude
  --project P --role tester --expires 30d` (UI too) makes `pm3_<kind>_<random 256 bits>`. The `pm3_` prefix lets secret
  scanners find leaks. It is shown once, stored as an HMAC-SHA256 under the server key, compared in constant time, and
  carries: owner user, project, a **role ceiling** (effective role is the lower of the token's role and the owner's
  current role), an optional **tier cap** (e.g. at most `active_safe`; the ROE can only narrow it further), expiry
  (default 30 days, at most 1 year), last use and use count, and revocation. A token dies with its owner's removal or
  demotion. Tokens never grant owner or server-admin, and cannot create tokens.
- **The actor is derived from the token, never from a client-supplied name.** A request with an agent token has
  `ActorKind::Agent` and the name stored with the token (`agent:claude`); the audit entry also records the token id and
  owning user. Today's `--actor` argument remains for single-user MCP only.
- **MCP for agents against a server** is a thin stdio-to-HTTPS bridge: `proxymind mcp --server https://host
  --token-env PROXYMIND_TOKEN`. The bridge calls the server's MCP endpoint; the server runs the tools in `pm-service`
  under the token's principal. The server-side code path is the one MCP uses today (`pm_mcp::call_tool`), so scope,
  tiers, approvals, redaction and untrusted tagging apply unchanged.
- **Agent tokens exist in single-user mode too** (a `~/.proxymind/tokens` file hashed, same format). That fixes the
  REST SDK problem (B2.2): a script or agent using REST can run as `agent:name` with a tier cap instead of as the
  human. The install token stays the full-power human credential, and the docs say that an agent that can read it is
  the human (F-1).
- **Plugin identities.** Plugins stay per user and run on the user's machine (ADR-0014); hooks never run on the server in
  3.x. An acting plugin talks to the server with a `plugin` token owned by the installing user, with the stricter tiers
  ADR-0014 gives `plugin:` actors and a role ceiling of tester. Server-side plugin execution is not part of Phase 3; if
  it is added later it needs `--require-signed` and owner-only enabling.
- **The `Authorization: Bearer` header is the only way tokens are sent.** Never in a URL or query string (logs, history,
  referrers).

### Roles (3.2)
Roles belong to a **project membership** (`memberships`: project, user, role). A separate **server admin** flag manages
accounts, OIDC and TLS but has no project access by itself. The first user is both.

| Capability | owner | tester | viewer |
| --- | --- | --- | --- |
| Read history, findings, reports, model, coverage | yes | yes | yes, with secrets redacted as agents see them (see open questions) |
| Send traffic (replay, fuzz, scan, workflows, streams) through the gate | yes | yes | no |
| Create and edit findings, hypotheses, identities, workflows, schedules, checks, notes | yes | yes | comment only (3.4) |
| Approve an agent's or plugin's pending action | yes | yes, for actions asked by their own tokens and by testers' tokens when the owner lets them | no |
| Change the ROE, scope, tiers, windows, data rules | yes | no | no |
| Manage members and roles; create tokens for others; revoke any session or token | yes | no | no |
| Configure listeners, upstream rules, integrations, OAST, model settings and keys | yes | no | no |
| Turn plugin hooks on, install plugins (per user) | on their own machine | on their own machine | no |
| Export or delete the project; seal and unseal | yes | export only | no |

- **Agents:** an agent acts with `ActorKind::Agent` and an effective role no higher than its owner's and its token's.
  The people-only set (approve, ROE, rules, listeners, keys, workflow triggers and edits, plugin switches, schedules)
  stays people-only **whatever the role**: an owner's agent token is still an agent. This is today's behaviour, now
  stated as a table.
- **Self-approval:** an approval binds actor, action and parameters (unchanged). A person approves what their agent asked.
  An ROE option `approvals.require_other_person: true` (default false) makes a person's own tiered requests need a
  different owner, for engagements that want four eyes.
- **Scope of roles:** a role says what a principal may do; the ROE and the gate still say what may be sent where. Role
  checks come first, then the gate. A viewer is refused active tiers before scope is looked at.

### Authorization in `pm-service`
- **A new module `pm-service::access`** holds the registry. `Perm` is an enum with one entry per kind of action (for
  example `HistoryRead`, `SendTraffic`, `FindingWrite`, `ApprovalDecide`, `RoeWrite`, `MembersWrite`,
  `TokensManage`, `IntegrationsWrite`), each with its allowed roles and a `people_only` flag. A `Principal` is
  `{ actor, user_id, role, project, token_id, session_id }`.
- **Every public `Service` method that touches project data begins with `self.require(&principal, Perm::X)?`.**
  Deny by default: `require` fails for an unknown `Perm`, a missing project, a revoked or expired token. The 53 scattered
  `actor.kind != Human` checks become `Perm` entries with `people_only`, so the whole rule set is readable in one file.
- **Enforcement is tested, not trusted:** (a) a source-scan test, like ADR-0017's check that no `store.lock()` remains,
  fails when a public `Service` method that takes an `Actor` or `Principal` does not call `require` first and is not on
  an explicit allow-list; (b) a matrix test drives every REST route and MCP tool as owner, tester, viewer, agent and
  an unauthenticated client and compares to an expected table committed in the repository.
- **`Actor` and the gate extend, they do not change shape.** `Actor { kind, name }` and `Actor::id()` (`human:alice`) keep
  their meaning so existing rows, approvals and tests stay valid. In multi-user mode the human's `name` is the account's
  immutable handle. The stable user id (`u_…`) travels in the `Principal` and goes to the audit log. `ActorKind`
  (human, agent, plugin, scanner) still drives the ROE's tier decisions (`tier_decision(kind, tier)`); the role adds a
  cap in front of it and the token's tier cap another.
- **`pm-policy` stays below `pm-service`** (ADR-0005): it learns `Role` only as an optional input to the verdict, never
  anything about sessions, tokens or accounts.
- **Redaction per principal.** The `Redactor` that swaps secrets for placeholders becomes one per user and project
  (placeholders are not shared between users), and records the host each secret came from; unredacting toward a
  different host needs approval (F-5).
- **Events and streams** are filtered by project membership and role, as intercept events are filtered to humans today
  (`events.rs`).

### Audit: who did what
- **Record version 2** adds `user_id`, `principal_kind` (session, token, local), `token_id` (never the secret),
  `project_id`, `session_id` (first 8 bytes of the stored hash) and `client_addr` to each entry. They are hashed into the
  record. `actor` stays `kind:name`. An append-only migration adds nullable columns; `verify` checks v1 records the old
  way and v2 records the new way, so existing logs still verify.
- **Keyed chain (F-6).** In server mode the v2 hash is `blake3::keyed_hash` with an audit key derived from the server
  key, which agents and project members cannot read. Anyone who can only write the project file cannot rebuild the chain.
  The server writes a **signed checkpoint** (head hash, count, time; Ed25519, key in the server home) every hour and on
  shutdown, exportable, so truncating the tail is detected. Single-user mode keeps the unkeyed v1 chain and the printed
  head hash.
- **Account events are audited** in a server-level security log with the same chain: login, failed login, logout,
  enrolment and removal of credentials, recovery, role change, token created, used for the first time, revoked, OIDC
  configuration changes and sessions revoked. Failed logins record the address and the claimed handle, never the
  password.

### Storage of users and credentials
- **Where:** a separate SQLite file, `server.db`, in the server home, owned by `pm-accounts` with its own append-only
  migration list under the same rules as `pm-store` (never edit a released migration; tracked in `user_version`;
  applied in `IMMEDIATE` transactions). It does not live in a project file, so handing a project to a client carries
  no accounts, hashes or sessions. Memberships name projects by id and are the server's, not the file's.
- **Tables (first migration set):** `users` (id, handle, display name, state, server_admin, created, last login),
  `credentials` (user, kind `password|totp|passkey|oidc`, public parts, created, last used), `recovery_codes`,
  `sessions`, `tokens`, `memberships`, `oidc_providers` (secrets encrypted), `invites`, `login_attempts`,
  `security_audit`, `checkpoints`.
- **Passwords:** Argon2id (the `argon2` crate `pm-vault` already uses), PHC string format, default 64 MiB, 3 passes,
  parallelism 1, a unique 16-byte salt from OS randomness, minimum 12 characters (as for sealed projects), checked
  against a bundled list of common passwords, no composition rules, no maximum below 256. The parameters are in the
  string, so a login with older parameters re-hashes (upgrade without a flag day). Memory use is bounded by a
  semaphore around hashing.
- **TOTP:** RFC 6238, 160-bit secret, SHA-1, 30 s, 6 digits (what authenticator apps support), one step of skew, a
  used step cannot be reused. The secret must be readable to verify, so it is stored **encrypted** (ChaCha20-Poly1305 under a
  key derived from the server key, with the user id as associated data).
- **Passkeys:** credential id, COSE public key, signature counter (a counter that goes backwards flags a cloned
  authenticator and the use is refused and audited), transports, AAGUID, a user-chosen name. Attestation is not
  requested.
- **Recovery codes:** 10 codes of 80 bits shown once at enrolment, stored as HMAC-SHA256, each single use.
- **Server key:** 32 random bytes in `<server home>/server.key` (0600) or from `PROXYMIND_SERVER_KEY`, or the OS
  keychain where available. HKDF (ring) derives separate keys for token HMAC, TOTP encryption, OIDC secret encryption
  and the audit chain. It is never written to a project file, log, audit detail or API response. Backups of `server.db`
  are useless without it; the docs say to store it separately.
- **Integration and OIDC client secrets** (3.5) use the same envelope or the keychain; they are never returned by the API
  (the listener-password masking pattern, `********`).
- **No plain-text credential is ever logged.** A test greps server logs and audit details after a login, a token
  creation and an OIDC login for the secret values used.

### Account recovery and bootstrap of the first owner
- **Bootstrap.** A server started with an empty `server.db` answers only the setup page. It prints a one-time **setup
  URL** with a random 128-bit token (stored hashed, valid 1 hour, single use) on the console. The setup page is served
  only on loopback, or over TLS, and throttled. The visitor creates the first account, which becomes owner and server
  admin, and must enrol a passkey or password plus TOTP before the page ends. The token is then dead.
- **Normal recovery.** A user who lost a factor uses another registered passkey or a recovery code. Otherwise an owner
  (or server admin) issues a **one-time enrolment link** (valid 1 hour, audited, forces a new credential and ends the
  user's sessions and tokens' use until they sign in again). There is no email-based reset: the server has no mail
  dependency, and a mail-based reset would make the mailbox the weakest factor. An owner may enable it later with an
  explicit setting.
- **Last owner locked out.** `proxymind server reset-owner` on the server host (requires write access to the server home,
  which is the same authority as the data) prints a new setup URL, ends all sessions and writes a `local_console` entry to
  the security log.
- **OIDC users** recover through their provider. Local break-glass is the owner's local account; the owner role never
  depends on OIDC.
- **Removing a user** disables the account, ends sessions and tokens, and keeps their authorship in the audit log and on
  findings (the id stays; the name is kept as written).

### Transport for the project server
- **TLS is required whenever the server listens beyond loopback.** It refuses to start otherwise. The one exception is
  `--behind-proxy` for a deployment where a reverse proxy terminates TLS: the server then listens on loopback or a
  private address, trusts `X-Forwarded-Proto` and `X-Forwarded-For` only from the configured proxy addresses, sets
  `Secure` cookies and the `__Host-` name, and checks `allowed_hosts`.
- **Certificates, in the order we recommend:**
  1. **Bring your own:** `--tls-cert` and `--tls-key` (PEM), reloaded when the files change, so Let's Encrypt via
     certbot, Caddy or a corporate CA works with no code in ProxyMind. This is the recommended setup for a team.
  2. **Reverse proxy** (`--behind-proxy`) for people who already run Caddy, nginx or Traefik.
  3. **Self-signed with pinning**, for labs, a single tester's server and agents on a trusted network: the server makes
     a P-256 key and a one-year certificate with `rcgen` (already a dependency), with the configured host names and IPs
     as subject alternative names, and prints and shows the **SHA-256 fingerprint of the public key (SPKI)**. A client
     connects with `proxymind login https://host --pin sha256:…` (or confirms the fingerprint interactively on first
     use, comparing it to the one the server printed) and stores the pin per server. The CLI, the desktop app and the MCP
     bridge then verify the pin and **fail hard** on a mismatch (never re-trust silently). Renewing the certificate with
     the same key keeps the pin; a new key needs the user to confirm the new fingerprint. A browser needs the user to
     accept the certificate once (documented), which is why this is not the team option.
- **Not used:** ACME inside ProxyMind (needs inbound ports 80 or 443, a larger dependency and renewal logic that
  certbot and Caddy already do well).
- **The interception CA is never used for the server certificate**, and its key never lives on the server. The project
  server stores traffic; the tester's machine intercepts (3.3 must keep this). Devices that trust the interception CA
  must gain nothing from trusting the server, and a server compromise must not yield the CA key (F-8).
- **TLS settings:** TLS 1.3 preferred, 1.2 allowed (rustls defaults with ring), HSTS when the certificate is not
  self-signed, no TLS compression, ALPN `h2` and `http/1.1`.

## Alternatives considered
- **OIDC only.** Least code to own, MFA by the provider. But a one-person firm or a lab needs an identity provider just to
  start, and a provider outage or compromise locks out or takes over everything. Rejected as the only source; kept as the
  second source.
- **Local accounts only.** Simplest to ship and to review. Teams that already have SSO would be told to create another
  password. Kept as the first step; the account model is built so OIDC adds a credential kind, not a new user model.
- **A reverse proxy does authentication and passes the user in a header** (oauth2-proxy, mTLS). No code, but the service
  would trust a spoofable header, and none of the roles, tokens or audit would be tied to a verified identity inside
  ProxyMind. Rejected as the only mode.
- **Stateless JWT sessions.** No session table, but no revocation, and a larger blast radius when a signing key leaks.
  Rejected for browser sessions (JWTs are verified only as OIDC ID tokens).
- **mTLS client certificates as the identity.** Strong, but certificate issuing and browser prompts make it a poor
  default. May come later as a token type for agents.
- **One shared team token (today's token, copied).** No identity, no revocation per person, no audit of who. Rejected: it
  is exactly what the single-user token is for.
- **SAML.** Large attack surface (XML signatures). Use an OIDC bridge such as Keycloak.
- **Accounts inside the project file.** Projects are copied to clients and laptops (ADR-0013): password hashes and
  sessions would travel with them, and opening a hostile project could inject accounts (F-2). Rejected: `server.db`.
- **Argon2id parameters lower than the vault's** (19 MiB, 2 passes is the common minimum). Cheaper per login, but the
  server's concurrency is bounded by a semaphore and logins are rare; we keep the vault's costs.
- **Email-based password reset and magic links.** Adds a mail dependency and makes email the weakest factor. Not now.

## Consequences
- Single-user mode, the install token, `--actor` and every existing client keep working; the new code is reached only
  through the server mode and the optional agent tokens.
- Authorization becomes one reviewable table plus two tests, so a forgotten check fails CI instead of shipping (F-7). The
  price is a mechanical edit of about 53 call sites and a `require` at the top of every public service method.
- The audit log gains user and token ids and, in server mode, a key; old logs still verify. Moving the audit key off the
  file is what makes F-6 closed for the server (not for single-user mode).
- A new crate (`pm-accounts`), a second SQLite file, a server key to protect and back up, and a WebAuthn and an OIDC
  implementation to maintain. The dependency and the review burden are the real cost.
- Passkeys tie the server to a host name. Operators who rename the server must re-enrol passkeys or keep a password plus
  TOTP account for the owner.
- **Risks.**
  - A WebAuthn library may bring OpenSSL (ADR-0003 prefers rustls and ring). Step 7 checks this first; the fallback is
    verifying ES256 and EdDSA assertions ourselves with ring and a small CBOR parser (a few hundred lines, with the
    WebAuthn test vectors).
  - An agent that can read the install token or the server key as the same OS user is the human (F-1). Tokens and the
    server design narrow this (a server on another host or user, scoped tokens), but a local single-user install cannot
    fix it; the documentation must say so.
  - TOTP secrets and OIDC client secrets are reversible by design; the server key protects them, and a stolen
    `server.key` with `server.db` exposes them.
  - Rate limiting by address is weak behind a proxy that hides addresses; `--behind-proxy` with trusted forwarding
    addresses addresses this, and per-account throttling does not depend on it.
  - F-2 (a project file is active content) is not solved by this ADR but is a precondition for shared and imported
    projects: step 0 below.

## Migration
Each step ships on its own and keeps `pm-service`'s public API unchanged (ADR-0005) until steps 4 to 6 change who calls it.

0. **Preconditions (no identity code; the Phase 3 gate needs them). Done 2026-11-21** (see the note below this
   step). Document F-1 in `docs/agents.md` and ADR-0005's
   consequences. Implement the safe open for F-2: a project not created by this install opens with schedules, workflow
   triggers and extra listeners off, upstream and rewrite rules shown as pending, the ROE displayed for confirmation,
   and `created_by`/`enabled_by` checked against the current user. Bind a saved model key to its provider host (B4.1).
   Test: a fixture project with an enabled schedule, a `0.0.0.0` listener and a hostile `base_url` does nothing until
   confirmed.

   *Done 2026-11-21.* F-1 is in `docs/agents.md` and ADR-0005. F-2 is `pm-service/src/trust.rs`: trust is a record in
   `<home>/project-trust.json` (project id from the `project_id` setting, so no migration was needed; a digest of the
   ROE, network settings, listeners, rewrite rules, session handling, assistant settings, schedules and enabled
   workflow triggers; who vouched and why). A project is trusted when this process created the file, when a person
   confirms the digest (`POST /project/trust`, `proxymind project trust`), or when a person edits it through the
   service while it was trusted; otherwise it is in safe mode, which holds back what the file would start (listeners,
   schedules, triggers, network settings, rewrite rules, session macros, the assistant) and refuses non-person actors
   at the gate. Scheduled scans and triggers run as the person who vouched, never as the stored `created_by` /
   `enabled_by`. **Existing projects:** not trusted until confirmed once (nothing in a file can tell a project this
   install used from a download); the choice was one click over silently trusting every file already on disk.
   The saved model key is bound to its server (`<home>/model-key-hosts.json`; B4.1). Tests:
   `crates/pm-service/tests/safe_open.rs`, `crates/pm-assistant/tests/assistant.rs`, e2e "Safe mode". Step 1 may now
   assume that a project it reads came from this install or was confirmed by a person; in server mode (3.3) the trust
   record moves into the server's own database, keyed by the same project id.
1. **The access module over the existing checks. Done 2026-11-21** (see the note below this step). Add `pm-service::access` (`Perm`, `Principal`, `require`); replace the
   53 `actor.kind != Human` checks with `Perm` entries marked `people_only`; single-user mode is the implicit owner.
   Test: the whole existing suite unchanged; the source-scan test; a table of every `people_only` action committed in
   `docs/`.

   *Done 2026-11-21.* `crates/pm-service/src/access.rs` holds `Perm` (32 entries, each with its roles and a
   `people_only` flag, in one `match`), `Principal` (an `Actor` plus a `Role`; `Principal::from_actor` maps a person
   to `owner` and every other actor to `tester`, so single-user behaviour is unchanged) and `Service::require` /
   `require_actor` (deny by default; a refusal is the `Invalid` error the old check returned, and is audited only where
   the old check audited). The scattered `actor.kind` checks and the `people_only` / `humans_only` helpers in
   `pm-service`, `pm-assistant` and `pm-cli` now go through it; uses of the actor's kind that are redaction or
   presentation stay, in an explicit allow-list with reasons. `docs/access.md` is the table, generated and kept in sync
   by `crates/pm-service/tests/access.rs`, which also holds the source-scan test (no authorization on the actor's kind
   outside `access.rs`) and the test that every `Perm` is used. Not yet done from the Authorization section: a `require`
   at the top of every public method (the scan that enforces it, and the matrix test, come with step 6, when roles
   become real), and the `Principal` fields `user_id`, `project`, `token_id`, `session_id`.
2. **Audit v2. Done 2026-11-21** (see the note below this step). Migration adding the nullable columns; record version 2 with user, token, project, session and address;
   `verify` handles v1 and v2; keyed chain and signed checkpoints for server mode behind a feature of the service. Test:
   old logs verify; truncating the tail is detected with a checkpoint; a v2 record with a changed `user_id` fails.

   *Done 2026-11-21.* Migration 26; version 2 records hash `principal_kind`, `user_id`, `token_id`, `project_id`,
   `session_id` and `client_addr` (canonical serialization in the `pm_policy::audit` module doc); `Principal` gained
   `user_id`, `token_id`, `session_id` and `client_addr` (all `None` in single-user mode) and `audit_context()`.
   Deviations from the text above, on purpose: the keyed chain is **HMAC-SHA256 over each record's hash** (ring, as
   for tokens) stored in a `mac` column, not `blake3::keyed_hash`, so the plain hash stays verifiable without the key
   and verification without the key says the key check was skipped; once a record is keyed every later one must be.
   The key is an `AuditKey` handed in by the caller (`Service::set_audit_security`); deriving it from `server.key` is
   step 3. Checkpoints (`pm_policy::checkpoint`) are Ed25519 (the evidence packs' primitives) over sequence, head
   hash, time and project id; they are stored in the project's `audit_checkpoints` table and exported as JSON
   (`proxymind audit checkpoint -o`, `verify --checkpoint`, evidence packs). Automatic checkpoints every N records
   happen only when the server calls `set_audit_security` with a signing key (the ADR's hourly and on-shutdown
   schedule is the server's to add). Single-user mode: on demand only, signed with `<home>/audit-checkpoint-key.pk8`.
   Not done: nothing yet supplies the client address, and the server security log is step 3. Tests:
   `crates/pm-service/tests/audit_v2.rs` and `pm-policy` unit tests.
3. **`pm-accounts`: users, passwords, TOTP, sessions, throttling,** with its own migrations and `server.db`. No HTTP yet.
   Test: Argon2 parameter upgrade at login, constant behaviour for unknown users, TOTP replay refused, recovery codes
   single use, throttle back-off, session expiry and rotation.

   *Done 2026-11-21.* `crates/pm-accounts` (depends on no other ProxyMind crate; `ring`, `argon2` as in `pm-vault`,
   `rusqlite` as in `pm-store`): `server.db` with append-only migrations (one so far), `ServerKey` (`server.key`, 0600,
   HKDF-SHA256 subkeys per purpose), users, invites and the one-time bootstrap and `reset_owner`, Argon2id passwords with
   upgrade at login and a dummy verification for unknown users, TOTP (own HOTP/TOTP on ring's HMAC; RFC 4226 and 6238
   vectors tested) with replay protection, recovery codes, the login flow (`login_password`, `login_second_factor`,
   `EnrolmentRequired`/`finish_enrolment`), sessions (hash only, idle and absolute expiry, rotation, revocation),
   per-account and per-address throttling, minimal `memberships`, and a chained security log. 48 tests in the crate.
   Deviations and decisions, on purpose:
   - **Password blocklist:** a short hand-written list of common 12+ character passwords, plus "not the username, not
     one character repeated", instead of a bundled large list (no list with a suitable licence is vendored yet; the
     check is one function and the list can grow without an API change).
   - **Pending sign-in token:** the password step returns a 5-minute token (stored as an HMAC, five attempts) for the
     second factor, and for first enrolment (`EnrolmentRequired`), which is how an owner with no second factor yet
     finishes setup. `bootstrap_owner` therefore makes a server admin who cannot sign in until a second factor exists.
     A holder of only the password of an account that has *no* second factor yet can enrol one first; invited users
     must therefore enrol straight after accepting their invite (the UI in step 4 does it in one flow). Admins clear a
     lost factor with `reset_second_factor`; there is no enrolment-link table yet (step 4 or 7).
   - **`credentials` is one generic table** (kind `password|totp|passkey|oidc`, `external_id`, `secret`, `counter`,
     `meta`), as the Storage section says, so passkeys (step 7) and OIDC links (step 8) need no schema change. `tokens`,
     `oidc_providers` and `checkpoints` come with their steps.
   - **Audit key:** `pm-accounts` does not depend on `pm-policy`; it exposes `ServerKey::derive(KeyPurpose::AuditChain)`
     (and `ApiToken` for step 5) and `pm-service` builds `pm_policy::audit::HmacKey::new(&bytes)` from it.
   - **Security log** (`security_audit`): HMAC-SHA256 chain under the audit-chain key. No signed checkpoints yet, so a
     deleted tail is not detected (with the project log's checkpoints, step 4 or later).
   - **Roles:** `memberships` (project id, user, owner|tester|viewer) are stored and a demotion or removal ends the
     user's sessions; what a role may do is `pm-service`'s table (step 6). `server_admin` is a column on `users`.
     Invites may be created by an active server admin, or by an owner of the invite's project.
   - **Throttling:** the account counter is keyed by an HMAC of the *claimed* handle (unknown names are throttled the
     same and the table holds no names); the address counter is not reset by a success, so a valid login of the
     attacker cannot clear it; both fade after an hour. The semaphore on concurrent hashes is a small `Gate` in
     `password.rs` (default 4).
   - **Not yet:** the HTTP layer, cookies and CSRF (step 4), the "fresh login within 10 minutes" check (sessions record
     `authenticated_at`; the check is step 4's), `Principal::session_id` plumbing (step 6), `PROXYMIND_SERVER_KEY` and the
     OS keychain as key sources (the `from_hex` constructor is there; the server home decides), the CLI
     (`proxymind server reset-owner` calls `Accounts::reset_owner`).
4. **Server mode in `pm-api`.** `proxymind serve --accounts`: session middleware replacing the token guard when accounts
   are on, cookies, CSRF layers, `allowed_hosts`, the setup page and bootstrap, TLS (own certificate, behind proxy,
   self-signed with pinning), refusal to listen beyond loopback without TLS. Test: route matrix without a session is 401,
   cookie flags, CSRF cases (no header, wrong origin, `Sec-Fetch-Site`), fixation, `next=` handling, plain HTTP refused on
   a non-loopback address, pin mismatch fails.

   *Done 2026-11-22.* `proxymind serve --accounts --server-home DIR [--listen] [--public-url] [--allowed-host]…
   [--tls-cert/--tls-key | --tls-self-signed | --behind-proxy --trusted-proxy IP…]` and `proxymind server reset-owner`;
   how to run it is `docs/server-mode.md`. Where things are: `pm-api/src/server_mode.rs` (the guard, `Me`, CSRF, cookies,
   `next=`), `auth_api.rs` (the `/api/v1/auth/…` endpoints, typed in the OpenAPI document), `listen.rs` (the pure
   `plan()` that refuses unsafe combinations, the TLS listener), `pm-tls/src/server.rs` (certificate reload, self-signed
   certificate, pins and the pin verifier); tests in `crates/pm-api/tests/server_mode.rs` (25), `crates/pm-cli/tests/serve.rs`
   (3) and unit tests in those modules. Decisions and deviations, on purpose:
   - **Project id** for memberships is the `project_id` setting inside the project file (`Service::project_id`, now public;
     a random value made once, already used for trust records and integration secrets), not the file's path: it survives
     renaming and moving the file, and a path would let two files at one path inherit each other's members. The first
     owner is made owner of that project at setup (a server admin has no project access by itself).
   - **The actor** is a `Me` (`actor`, the account and session, the client address) that the guard puts in the request;
     single-user mode puts `AppState::actor` there, so all ~145 handlers changed mechanically from `st.actor` to
     `me.actor`. In server mode it is `human:<handle>` (the stable user id when the handle has a `+`, which actor names
     cannot hold). `Me::principal()` builds the `Principal` with user id, session reference and address, but **service
     methods still take an `Actor`, so audit records do not carry user, session and address yet and every member acts as
     a human**; both come with step 6, as does the keyed chain's checkpoint schedule (`serve` does hand the derived audit
     key to `set_audit_security`).
   - **Sign-in as the API shapes it:** `login` answers `authenticated`, `second_factor_required` or `enrolment_required`
     with the 5-minute pending token; setup and accepting an invite continue straight into the same flow, so an owner or
     any invited user lands in TOTP enrolment before a session exists. Signing in again while signed in is the step-up
     (the old session of the same user is ended, a new id is issued, `authenticated_at` is fresh); there is no separate
     re-authentication endpoint. Fresh-login (10 minutes, on the server's clock) is required for invites (create and
     revoke), disabling, enabling and resetting users, TOTP enrol and removal, recovery codes and password change.
   - **Links with tokens put the token in the URL fragment** (`/#setup=…`, `/#invite=…`): a browser never sends it to a
     server, and it stays out of logs and `Referer`. The UI reads `location.hash` and removes the token from the address bar.
   - **Setup is served** over TLS, behind a trusted proxy that says HTTPS, or to a peer on loopback when there is no
     proxy; a proxy that is on loopback does not count as "this machine".
   - **Public URL and origins:** with `--public-url` the only allowed `Origin` and `Host` are that one (plus
     `--allowed-host` names); without it (loopback only) the loopback names and the listen port. Behind a proxy and beyond
     loopback the URL is required. `--behind-proxy` needs `--trusted-proxy`, a loopback or private listen address and no
     TLS flags. A peer that is not a trusted proxy is never believed about `X-Forwarded-*`.
   - **Pin text** is `sha256:` plus standard base64 of the SHA-256 of the certificate's SubjectPublicKeyInfo (as curl's
     `--pinnedpubkey` and Chromium's SPKI lists use); hex is accepted on input. `PinVerifier` ignores host names and
     validity dates, as the key is the identity. It lives in `pm-tls::server` for step 5's `proxymind login` and the MCP
     bridge.
   - **TLS listener:** handshakes run in their own tasks (10 s timeout, at most 256 at once), so a failed or stalled one
     never touches the accept loop. ALPN offers `h2` (axum's `http2` feature is now on) and `http/1.1`. HSTS is sent
     with an own certificate and behind a proxy that says HTTPS, never with a self-signed one.
   - **`serve` does not run the interception proxy unless `--proxy ADDR` is given.** The CA key should stay on the
     tester's machine (F-8, ADR 3.3); everything else `ui` starts (service, scheduler, workflow triggers, notifier, plugins)
     runs through the one shared function `start_runtime`.
   - **Not done, left for later:** `pm3_` tokens (step 5; `server_mode::authenticate_bearer` is the hook, and the install
     token is refused as a bearer); roles enforced by `require` and events filtered by membership (step 6; an event stream
     already open outlives its session's revocation until then); the server's signed audit checkpoints; member management
     endpoints (invites and `set_membership` through the library only); passkeys and OIDC.
     Account events are in `pm-accounts`' security log, which already records every sign-in, failure, logout, credential
     change, invite and admin action, so the API adds no second log (its entries carry no client address for admin actions
     yet).

   *UI done 2026-11-23.* The web UI has the server-mode screens (`docs/server-mode.md`, "The web UI"). Where things are:
   `ui/src/Root.tsx` (mode detection and the setup, invite, sign-in, not-a-member and re-authentication screens),
   `ui/src/authparts.tsx` (the shared steps: second factor, enrolment, recovery codes), `ui/src/pages/Account.tsx` (the
   Account and Users & invites pages), `ui/src/api.ts` (the 401 and `fresh_login_required` hooks), and the browser test
   `ui/tests/e2e-server.mjs` (run by `npm run test:e2e`). Decisions, on purpose:
   - **Mode is detected once at start-up** with `GET /auth/state`: only a 200 with `server_mode: true` is server mode. In
     single-user mode that URL answers `{"server_mode": false}` (with the install token; the other account endpoints are
     404 there) or 401 (no token), and the UI renders the app as before, with no extra screen and no failed request.
   - **One backend addition:** `TotpEnrolmentResponse` now has `qr_svg`, the otpauth URI as a self-contained SVG made by the
     same `qr_svg` function the proxy-setup page uses (`pm_service::qr_svg` is public now). The UI has no QR code of its
     own, and adding a library was ruled out. The secret is in the response anyway; the SVG adds nothing the client did
     not already get.
   - **A lost session (any 401 `unauthenticated`) unmounts the app** (closing the event stream), shows the sign-in with a
     notice and returns to the same `#/route` afterwards. A 403 `fresh_login_required` opens a re-authentication dialog
     (password, then code), and the call is repeated once after it. `not_a_member` has its own screen.
   - **No secret is kept:** passwords, codes, the TOTP secret, recovery codes and tokens live in component state only (never
     in `localStorage`, `sessionStorage` or the console). Recovery codes are offered for copy and as a `data:` download.
5. **Tokens.** `pm3_` tokens for agents, CI and plugins, in both modes; `proxymind token …`; `proxymind login`; the MCP bridge
   to a server. Test: actor derived from the token, role ceiling and tier cap, expiry, revocation takes effect on the next
   request, a token cannot create tokens, tokens never appear in logs or audit detail.

   *Done 2026-11-23.* `pm3_<kind>_<64 hex>` tokens work in both modes, with `proxymind token`, `proxymind login` and
   `logout`, a stdio-to-HTTPS MCP bridge (`proxymind mcp --server`), the Tokens panel in the web UI and an MCP endpoint
   on the server (`POST /api/v1/mcp`). How to use it is `docs/server-mode.md` ("Tokens, login and the MCP bridge") and
   `docs/agents.md`. Where things are: `crates/pm-accounts/src/token.rs` (the rules both modes share: format, hash,
   name, ceiling, cap, lifetime, use bookkeeping), `tokens.rs` (the `tokens` table of `server.db`, migration 2),
   `token_file.rs` (single-user `<home>/tokens.json`); `pm-api/src/{tokens_api,mcp_api,server_mode,lib}.rs`;
   `pm-policy` (`Policy::set_tier_cap`); `pm-cli/src/{token_cmd,remote}.rs`; `ui/src/pages/Tokens.tsx`. Tests:
   `pm-accounts` (60, 12 of them for tokens), `pm-api/tests/{tokens,server_mode}.rs`, `pm-policy/tests/tier_cap.rs`,
   `pm-service/tests/tier_cap.rs`, `pm-cli/tests/tokens.rs`, both browser tests. Decisions and deviations, on purpose:
   - **Stored as HMAC-SHA256** under the `ApiToken` subkey (server mode) or under a key in `<home>/tokens.key`
     (single-user, 0600, also refused when others can read it); lookup is by the hash and the digests are then compared
     in constant time. The single-user file `tokens.json` (0600; refused and every token then fails when group or
     others can read it) holds the same records as the table; writers (the CLI, the running UI's bookkeeping) take a
     lock file and replace the file atomically, readers read it at every request, so a CLI revoke is seen by a running
     `proxymind ui` at once.
   - **Single-user tokens have no owner and no project** (`user_id` and `project_id` are empty): the owner is whoever owns
     the home, and a token works for whatever project that install serves. The brief for this step asked for a project
     id; there is none to bind to before a project is open, and binding to the file's id would make `proxymind token
     create` open a project. Server-mode tokens carry both.
   - **One live token per actor id.** A name is unique among live tokens of its kind (any case). That is what makes the
     tier cap enforceable by actor id (below) and makes every audit line name exactly one credential.
   - **Tier cap in the gate, by actor id.** Service methods take an `Actor`, so the cap cannot ride a request without
     changing every signature. `Policy` keeps `caps: actor id -> Tier`; the API's guard sets it each time a token
     authenticates (`Policy::set_tier_cap`, a person is never capped) and `Policy::evaluate` checks it *before* scope,
     windows and the rules, so it holds for every path that asks the gate (REST, MCP, the CLI, background scan tasks the
     actor started) and for approved actions, which are evaluated again when they run. The rules can only narrow it. A
     cap is held for the actor id until another token of that name sets another, also after the token is revoked (a
     scan the token started stays capped). Not capped by it: actions that are not tiered (writing a finding, a note).
     `roe_get` shows the cap (`credential_tier_cap`, tiers above it read `deny`).
   - **Effective role = lower of the token's ceiling and the owner's current role,** read at every request (server
     mode). What is enforced now: a **viewer** (by ceiling or by the owner's role) gets only `GET`/`HEAD`/`OPTIONS` on the
     REST API (`403 read_only_token`), may initialize and list tools on the MCP endpoint but not call them, and is held
     to tier `passive` by the gate; an owner demoted to viewer narrows their tokens at once, a removed membership or a
     disabled account kills them (and revokes the rows, so enabling the account again does not bring them back).
     **Not enforced yet (step 6):** the rest of the roles table for tokens (a tester's token has the people-only rules
     of every agent and nothing finer; `Perm`s per role are still not asked of service methods), and the project audit
     records of a token's actions do not yet carry the token id and owner (`Me::principal()` has them; service methods
     take an `Actor`). The token's own management (create, revoke) is audited with the full principal.
   - **People manage tokens, tokens never do.** `Perm::TokensManage` (owner, tester; people only) and
     `TokensManageOthers` (owner, people only) are in the access table. In server mode one's own tokens need no fresh
     sign-in (the ADR lists creating and revoking tokens *for other users*); for others, an owner and a fresh sign-in
     (`for_user`). Tokens cannot use the account endpoints at all (`403 token_not_allowed`). A viewer cannot manage
     tokens.
   - **CSRF for bearer requests (server mode).** A request with a `pm3_` bearer token and **no session cookie** is exempt
     from the Origin / `Sec-Fetch-Site` layer and does not need `X-ProxyMind: 1`: there is no ambient credential for a
     cross-site page to use, and curl, CI jobs, the SDKs and the MCP bridge send neither. A request that has the
     session cookie (valid or not) gets the full cookie-path checks whatever else it carries, and then acts as the
     person (the cookie wins). A bearer that is not a `pm3_` token (the install token) gets the checks as before, then
     401. In single-user mode the same: a `pm3_` bearer without the `pm_token` cookie needs no `X-ProxyMind`; the install
     token as a bearer still does. Host checks apply to both.
   - **Last use and use count** are written at most once a minute per token (counted in memory in between; a listing
     includes the pending count; a crash loses at most a minute's count). The first use is a security-log entry.
   - **Security log** (server mode): `token_created`, `token_first_use`, `token_revoked`, `tokens_revoked` (owner
     disabled or removed) and `token_failure` (reason, address and the token's id when known, never a value). Failures
     are logged in their own throttle bucket: after 20 from one address the entries thin out with the login back-off,
     and a flood can neither fill the log nor lock anyone out of signing in. Single-user mode logs a refusal to stderr at
     most once a minute and has no security log.
   - **`proxymind token`** works on the install's file (single-user) or, on the server host with `--server-home DIR
     --user NAME`, on `server.db` (the write access to the home is the authority; the security log says
     `local_console`). Away from the host, server tokens are made in the web UI or with `POST /api/v1/tokens`.
   - **`proxymind login URL [--pin sha256:…]`** saves the address, pin and token in `<home>/servers.json` (0600) only
     after `GET /api/v1/status` has answered for that token over a verified connection. Without `--pin` the
     certificate must verify against the bundled public roots (the roots upstream verification uses; a private CA
     therefore needs `--pin`); with it, `pm_tls::server::pin_client_config`. A mismatch is an error naming both pins,
     never retried and never saved. A saved pin is used when none is given and replaced only by one given on the command
     line (`proxymind logout URL` forgets the entry). `http://` is accepted for loopback addresses only. The token is
     read from `--token-env VAR`, else a hidden prompt on a terminal, else one line of stdin.
   - **MCP.** `POST /api/v1/mcp` takes one JSON-RPC message or a batch (204 for a notification) and runs
     `pm_mcp::McpServer::handle` under the request's actor, built per request around the shared `Service`; a message
     cannot name another actor. A session or the install token reaches it too and acts as that person. The bridge
     (`proxymind mcp --server URL`) posts each stdin line, answers errors as JSON-RPC errors per request id, and ends at
     once on a certificate or pin failure. Plain `proxymind mcp --actor …` is unchanged.
   - **Left for step 6:** roles per tool and route for tokens (above), the token id and owner on every audit record,
     filtering events and the MCP endpoint by membership, the per-user redactor, and the open question of server-side
     approval routing (a tester approving their own token's pending actions).
6. **Roles and memberships (3.2).** Per-project roles, the matrix in this ADR enforced by `require`, the people-only set
   fixed for agents of owners, the ROE option `approvals.require_other_person`, per-user redactor with host binding (F-5),
   events filtered by membership. Test: the matrix test over every REST route and MCP tool for each role and for an
   unauthenticated client.

   *Done 2026-11-25.* Roles are enforced on a project server; the matrix is `docs/access-matrix.md` (generated and
   tested by `crates/pm-api/tests/matrix.rs`) over the table in `docs/access.md`. Where things are: `pm-service/src/access.rs`
   (56 `Perm`s, the principal registry, request scope, `require*`), `pm-api/src/route_perms.rs` (route to `Perm`),
   `pm-mcp::tool_perm` (tool to `Perm`), `pm-api/src/{server_mode,auth_api,routes}.rs` (guard, members, stream watch),
   `pm-store` migration 27 (who asked, on approvals), `pm-accounts` (`LastOwner`), `ui/src/pages/Account.tsx` (Members),
   `ui/tests/e2e-server.mjs`. Design and deviations, on purpose:
   - **Who is this actor?** Service methods still take an `&Actor`. `Service::set_access_control(true)` (done by
     `AppState::with_server_mode`) switches `principal_of(actor)` from `Principal::from_actor` to a registry that the
     API's guard fills on every authenticated request, from the membership (session) or the token's effective role, after
     `server.db` was read. An actor nobody registered is a **viewer**, never an owner; a non-person is never above
     `tester`, so an owner's token is an agent. Single-user mode keeps `from_actor` and the `Invalid` refusal (server mode
     refuses with `Forbidden`, a 403, text `access denied: ...`). Work the service starts itself registers too: scheduled
     scans and triggers (`run_as`) as `tester` with no account, an AI scan's agent and workers inherit the starter's
     role. A demotion or removal through the API updates every registered actor of the account at once
     (`principals_of_user_changed`); an open event stream re-checks its session or token every two seconds and ends when
     it no longer holds.
   - **Every public method asks.** 89 methods gained `self.require_actor(actor, Perm::X)?` as their first statement; 158 of
     the public `Service` methods that take an actor now ask before touching the store, gate or network (a source-scan test,
     `tests/access.rs`, fails otherwise) and 16 are on an explicit allow-list with reasons. Reads and calls that take no
     actor (listing identities, approvals, the audit log, settings, findings) are not covered by that scan; the API
     checks the route table before the handler, and MCP the tool table, which is what keeps a viewer out of them.
   - **Second line in the API, on purpose.** The ADR puts enforcement in `pm-service`; it is there. The route table in
     `pm-api` repeats it before the handler so the handlers that call a method without an actor cannot be a hole, and the
     matrix test proves every route and tool. Single-user mode does not use the route table.
   - **Audit context per request.** `Service::in_request` scopes the request's principal around the handler (a
     `tokio::task_local`); every audit record written for that actor meanwhile carries its user, token, session and
     address. Work spawned from a request (scan tasks, fuzzer attacks) runs outside the scope and falls back to the
     registry (user, token, the last session and address seen); the record may name the latest session of that account.
     In single-user mode a `pm3_` token's requests carry the token id.
   - **Viewers see redacted traffic.** `redacts_for` is true for a viewer even when the ROE's `redact_before_llm` is off;
     history, exchange detail (the REST `GET /exchanges/{id}` hides the exact bytes for a viewer), search, evidence in
     reports (`report_render_for`), findings, proofs, the model and the events pass the redactor. REST agent tokens still
     read actor-less JSON as stored (unchanged).
   - **Per-user redactor (F-5), half done.** One redactor per account (a token shares its owner's; single-user mode shares
     one), so a placeholder means nothing to another user. **Host binding is not done:** a placeholder still unredacts toward
     any in-scope host. It needs a host recorded at every `redact` call site and an approval step in every send path
     (`replay`, `race`, `group`, `identity`, `session`, `streams`, `ws_replay`, scans); left for the security review (step 9).
   - **Events** are filtered per topic by `Perm` (`topic_perm`): viewers get no intercept, approvals, audit, plugin or
     Collaborator topic, and payloads are redacted.
   - **Approvals.** The row stores the asking account, token and the account's role (`requested_*`). An owner decides any;
     a tester only what they, or their own tokens, asked, plus other testers' tokens when the ROE says
     `approvals.testers_decide_team: true` (default false); a viewer none. `approvals.require_other_person: true` (default
     false): nobody decides what they or their own tokens asked, so a different owner must (it applies to tokens as well
     as the person, a choice for four eyes). Both options matter only on a server; one person approves everything in
     single-user mode.
   - **Members.** `GET /auth/members`, `PUT /auth/members/{user_id}`, `DELETE /auth/members/{user_id}` for the project's
     owner (fresh sign-in for changes); the last owner is never demoted or removed. Demotion and removal end sessions
     (pm-accounts); tokens follow the role at the next request, and removal revokes them.
   - **Not done.** Export-project, delete and seal are not service methods (they are file operations; 3.3 owns them), so the
     table has no entry for them; "viewers comment" waits for 3.4; the server's signed checkpoint schedule and the
     host binding above are for step 9; an agent token's REST reads of actor-less routes are unredacted as before;
     event streams of single-user tokens are not closed on revocation.
7. **Passkeys.** Decide the library or the in-house verifier (OpenSSL check first), enrolment, login, counter checks,
   recovery by link and by `reset-owner`. Test: WebAuthn vectors, a cloned authenticator is refused, host-name change
   behaviour documented.

   *Done 2026-11-25.* Passkeys work in server mode: enrol, sign in (with a username and without), rename, remove, setup and
   invites with a passkey, recovery by a one-time enrolment link, and the server-wide "require a passkey" setting. How to
   use them is `docs/server-mode.md` ("Passkeys"). Where things are: `pm-accounts/src/webauthn/` (`cbor.rs`, `cose.rs`,
   `mod.rs`: the verifier; `soft.rs`: a software authenticator for tests), `pm-accounts/src/passkeys.rs` (ceremonies,
   storage, counter, enrolment links, the setting), `pm-accounts` migration 3, `pm-api/src/passkey_api.rs` (the routes),
   `pm-api/src/{server_mode,auth_api,listen}.rs` (the guard's restricted session, the state endpoint, the RP id),
   `ui/src/{passkeys.ts,passkeyparts.tsx,Root.tsx,pages/Account.tsx}`, and the browser test `ui/tests/e2e-server.mjs`
   (Chromium's virtual authenticator). Decisions and deviations, on purpose:
   - **Library: our own verifier, with ring.** The OpenSSL check came first. `webauthn-rs` (`webauthn-rs-core` 0.6.2) no
     longer needs OpenSSL (`cargo tree` shows none; it moved to RustCrypto), so that was not the reason. It brings 231
     crates, 96 of them not yet in this workspace's lock file, among them a second cryptography stack (the
     release-candidate `rsa` 0.10.0-rc.19, `p256`, `ecdsa`, `aes`) next to ring, plus x509 and attestation-statement
     code for attestation this server never asks for (`attestation: "none"`). ADR-0003 prefers rustls and ring, and ring
     already verifies what WebAuthn needs: ES256 (ECDSA P-256, DER signatures), Ed25519 and RS256. What is left is a
     strict CBOR decoder (bounded depth 8 and 256 entries per container, definite lengths only, no tags, floats or
     duplicate keys, no trailing bytes, a declared length larger than the input is refused before any allocation), COSE
     key parsing and the checks of the specification: about 700 lines with tests, no new dependency, nothing for
     `cargo deny` to look at and no change to `desktop/Cargo.lock`. The cost is ours to maintain; the allow-list is three
     algorithms and the verifier never looks at an attestation statement.
   - **Checks, in order** (registration and assertion): `clientDataJSON` `type`, the challenge (constant-time compare),
     `origin` exactly one of the server's origins, no `crossOrigin: true` and no `topOrigin`; `rpIdHash` equals SHA-256 of
     the RP id; user present and user verified both set (a sign-in without user verification is refused, always); backup
     state implies backup eligibility; for a registration the credential data and a COSE key in the allow-list, the
     credential id 16 to 1023 bytes and the id the browser reports equal to the attested one; extension data is parsed
     when its flag is set and nothing may trail when it is not; for an assertion the signature over `authenticatorData ||
     SHA-256(clientDataJSON)`. Tests: three captured real ceremonies (a Yubico key's ES256 assertion, a YubiKey 5 Bio's
     Ed25519 registration, Edge on macOS's ES256 registration with user verification; sources in the test file's header),
     RFC 8032's first vector, a software authenticator for ES256, Ed25519 and RS256, one test per refusal (origin, RP id,
     challenge, type, user presence, user verification, cross-origin, top origin, signature, trailing bytes, an algorithm
     outside the allow-list), and random and mutated bytes into the CBOR decoder and the verifier.
   - **Challenges** are 32 bytes from the OS, kept in memory for five minutes, **single use** (taken out of the table before the
     response is read, so a failed attempt uses its challenge up) and **bound to who asked**: an enrolment to the user and
     the session that began it, a setup, invite or enrolment-link registration to its token and chosen username, a
     sign-in to the name it claimed. The table is capped (4096; the oldest go) because anyone may ask for sign-in options.
     A restart loses open ceremonies: one retry.
   - **RP id and origin.** The RP id is the host name of the public origin `listen::plan()` computes (`ListenPlan::passkey_rp`);
     the accepted origins are the allowed origins on that name or below it. An IP address is no RP id: a server whose public
     URL is an IP address has no passkeys (the state endpoint says why). The one exception is a loopback-only server
     without `--public-url`, which offers `localhost`. The UI offers passkeys only on a page whose host is the RP id or
     below it. Renaming the server invalidates every passkey: keep an owner with a password and an authenticator, or plan
     the name first.
   - **Storage.** `credentials` kind `passkey`: `external_id` the credential id (unique across the server), `secret` the
     COSE key as registered, `counter`, `label` the name, `meta` JSON (transports, AAGUID, backup flags, algorithm). The
     only migration (3) adds `enrolment_links` and `server_settings`. At most ten passkeys per account.
   - **Counter.** If either the stored or the new counter is non-zero, the new one must be greater; otherwise the sign-in
     is refused like any failure and the security log gets `passkey_clone_suspected` (credential row id, both counts). A
     counter that is always zero is allowed. The stored counter does not move on a refusal.
   - **No username leak.** Sign-in options with a username for a name that is unknown, disabled or has no passkey carry
     one to three decoy credential ids from an HMAC of the name under a key derived from the server key (`PasskeyDecoy`),
     so the same name always gets the same answer and its shape is the real one's. Residual: an account with more than
     three passkeys shows a count no decoy has, and a real id is as long as the authenticator makes it. Without a
     username the list is empty and nothing is revealed. Every refusal (unknown credential, another user's credential,
     a user handle that is not the credential's owner's, a bad signature, a clone, a disabled account) is the same
     `invalid credentials`, after the same throttle and security-log bookkeeping as a password failure (the account counter
     is shared with the password step).
   - **A passkey is a complete sign-in** (`auth_method` `passkey`, a fresh session like any other) and **counts as the owner's
     second factor**. A password sign-in for an account that has a passkey and no authenticator is refused with a named error
     (`passkey_required`) instead of offering to enrol one, so a stolen password cannot add a factor to such an account; an
     authenticator may be turned off by an account that has a passkey. Passkeys are not offered as a second step after a
     password: they replace both.
   - **Require a passkey** (`PUT /auth/settings/passkey-required`, server administrator, fresh sign-in, audited, and the
     administrator needs a passkey of their own so the setting cannot lock them out). The rule when on: every account must have a
     passkey. An account without one signs in with password and authenticator as before, but the session is
     **restricted**: the guard answers 403 `passkey_enrolment_required` to everything except `GET /auth/me`, `POST
     /auth/logout` and the passkey endpoints, and the UI shows only "Add a passkey to continue". An account that has a
     passkey cannot sign in by password at all (so the password cannot be phished into a session), and its last passkey
     cannot be removed. Recovery codes are part of the password route, so they stop working for such an account too: an
     owner issues an enrolment link. Tokens are machine credentials and are not affected.
   - **Removing** a passkey needs a fresh sign-in, ends the account's other sessions (the session making the request gets a
     new id), and is refused when it would leave the account unable to sign in or without a second factor: the last
     passkey of an account without a password and authenticator (`last_passkey`), of an owner or administrator who has a
     password but no authenticator (`second_factor_required`), or while the server requires passkeys (`last_passkey`).
   - **Setup, invites and recovery.** The setup page and an invite offer a passkey (recommended) or a password; with a passkey the
     account has no password at all, and the setup token or invite is used up only when the registration verifies (a failed
     one leaves it usable). `proxymind server reset-owner` is unchanged: its setup URL's page offers a passkey too. A
     **one-time enrolment link** (`POST /auth/users/{id}/enrolment-link`; `#enrol=<token>`, 256 bits, valid one hour, single use,
     stored as an HMAC, a newer link replaces an unused one) is the recovery for someone who lost every way in, including a
     passkey-only user who lost their device. Who may issue one: a server administrator for any other account; an owner
     of the served project for a tester or viewer of it, never for a peer owner or an administrator (a project owner must not
     be able to take over a peer's or an administrator's account), never for oneself; always with a fresh sign-in.
     **Issuing it ends the user's sessions and revokes their tokens** (deviation: the text above says tokens' use is
     suspended until they sign in again; a suspension would need a new state, and a revoked token stays revoked, so they make new ones).
     **Redeeming it replaces how the account signs in**: the password, authenticator, recovery codes and every passkey are
     removed, and the person registers a new passkey (signed in at once) or chooses a new password (then enrols an
     authenticator, as after an invite). The links printed for invites and enrolment links use the origin the issuer's
     browser used when it is one of the server's own, so the link opens on the host name passkeys belong to.
   - **Routes** (all under `/api/v1/auth`; the access matrix lists them): `POST /passkey/login/options`, `POST /passkey/login`,
     `POST /setup/passkey/options`, `POST /setup/passkey`, `POST /invite/passkey/options`, `POST /invite/passkey`,
     `POST /enrol-link/info`, `POST /enrol-link/passkey/options`, `POST /enrol-link/passkey`, `POST /enrol-link/password`
     (public, with the same CSRF layers and throttling as the password sign-in), `GET /passkeys`, `POST /passkeys/options`,
     `POST /passkeys`, `PUT /passkeys/{id}`, `DELETE /passkeys/{id}`, `PUT /settings/passkey-required`, `POST
     /users/{id}/enrolment-link`. `GET /state` gains `passkey_supported`, `passkey_rp_id`, `passkey_note`, `passkey_required`
     and, with a live session, `passkey_count`; `GET /me` gains `passkey_count` and `passkey_enrolment_required`.
   - **Tests.** `pm-accounts`: 42 new (19 verifier, CBOR and base64url; 23 for the flows: every algorithm, single use and expiry of
     challenges, binding to user and session, each registration refusal, uniqueness of credential ids across accounts, another user's
     credential, a counter going backwards (refused and audited) and zero counters, throttling shared with passwords, decoys, disabled
     accounts, rename and the removal rules, the require setting, setup and invites with a passkey, the enrolment link and who may
     issue it, bounds, and no key material in the security log); `pm-api`: `tests/passkeys.rs` (11, over a real socket: enrolment, both
     sign-in modes, indistinguishable refusals, throttling and clones, the owner's last second factor, the require rule with the restricted
     session, setup, invites, enrolment links, the CSRF layers and size limits, and no key, signature, link or session id in any answer,
     log or audit entry), the secrets test of `server_mode.rs` extended with a passkey flow, unit tests for the RP id, the link origin and the
     restricted routes; the access matrix; `ui/tests/e2e-server.mjs` with Chromium's virtual authenticator (add, sign in, rename, remove,
     the require rule and the gate, an enrolment link, setup with a passkey on a second server); `ui/tests/passkeys.test.mjs`.
   - **Not done.** Attestation is not requested and not verified (no allow-list of authenticator models); no browser autofill
     ("conditional UI") on the username field; no list or revoke of unused enrolment links (a new one replaces the old; they
     expire in an hour) and no `proxymind` command to issue one on the server host (`reset-owner` is the console path); the host
     name cannot be changed without re-enrolling; tokens ignore the require rule; passkeys are not offered as a second factor after a password.
8. **OIDC.** Provider configuration (owner only), PKCE, discovery, JWKS caching and rotation, claim mapping with the
   owner-never-from-claims rule, optional email linking and auto-create by domain. Test with an in-process fake provider
   (as the HTTP/3 work has an in-process server): wrong `iss`, `aud`, `nonce`, expired token, mix-up, replayed `code`,
   open redirect, a claim asking for owner.
9. **Security review for the gate** (below), and update `docs/threat-model.md`: close or accept each finding with the
   owner's name and date.

**What the Phase 3 gate's security review must check for this ADR**, in addition to the checklist in
`docs/threat-model.md` section 9:
- Every route and MCP tool is in the matrix test; no `Perm` is missing; the source-scan test passes with an empty
  allow-list or one the reviewer accepts.
- Session id entropy and storage (hash only), cookie flags in both TLS and loopback modes, rotation and revocation, and
  CSRF layers on every mutating route.
- Login: enumeration, timing, throttling, Argon2 concurrency cap (no memory exhaustion from parallel logins), TOTP replay,
  recovery codes, passkey counter and RP id handling, setup-token lifetime and single use.
- OIDC: exact `redirect_uri`, `iss` pinning and the RFC 9207 check, `aud`, `nonce`, `exp`, PKCE, JWKS fetch and cache
  rules (no fetching from claims), algorithm allow-list (no `none`, no HS* with the client secret), the owner-never-from-claims rule.
- Tokens: HMAC storage, shown once, scope and ceiling, expiry, revocation on owner change, absence from logs and audit.
- The audit chain: v1 and v2 verify, key handling, checkpoint signing, tail truncation test.
- Server key handling and backup advice; secrets absent from project files, logs, audit detail, API responses and exports.
- TLS: refusal without TLS beyond loopback, pinning behaviour, certificate reload, no use of the interception CA.
- F-1 documented and F-2 fixed (step 0); no open high-severity finding in `docs/threat-model.md`.

## Open questions for the owner
Answered 2026-11-21: the owner confirmed 1, 3, 4 and 11 as recommended; 2, 5–10 take the recommendations.

1. **Identity sources.** Both, local first and OIDC second within Phase 3 (recommended), or local only, or OIDC only?
2. **Second factor.** Allow passkeys and password plus TOTP from the start, owner always needs a second factor, and let the
   owner require passkeys per server (recommended); or passkeys only (stricter, harder for headless setups)?
3. **Joining.** Invite only, with OIDC auto-create off by default and capped at `viewer` (recommended); or allow open
   sign-up from an OIDC domain with `tester` by default?
4. **What a viewer sees.** Redacted views, like agents (recommended: a viewer is often a client or a manager); or raw
   traffic too?
5. **Four eyes.** `approvals.require_other_person` off by default and available in the ROE (recommended); or on by default
   for multi-user servers?
6. **Session lifetime.** Idle 8 hours, absolute 7 days (recommended); or longer for convenience?
7. **Certificates.** Offer bring-your-own, reverse proxy and self-signed with pinning, refuse plain HTTP beyond loopback
   (recommended); or require bring-your-own only?
8. **Where accounts live.** A separate `server.db` and a new `pm-accounts` crate (recommended); or tables in the project
   file (not recommended, see alternatives)?
9. **WebAuthn implementation.** Use a library if it does not require OpenSSL, otherwise our own ring-based verifier
   (recommended); or accept OpenSSL for the server build?
10. **Agent token defaults.** Role `tester`, 30 days, no extra tier cap beyond the ROE (recommended); or default `viewer`
    and require the owner to raise it?
11. **Step 0 timing.** Do the F-1 documentation and F-2 safe open now, ahead of the rest of Phase 3, because they apply to
    single-user installs today (recommended); or only with 3.3?
