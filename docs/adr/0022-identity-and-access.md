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
1. **The access module over the existing checks.** Add `pm-service::access` (`Perm`, `Principal`, `require`); replace the
   53 `actor.kind != Human` checks with `Perm` entries marked `people_only`; single-user mode is the implicit owner.
   Test: the whole existing suite unchanged; the source-scan test; a table of every `people_only` action committed in
   `docs/`.
2. **Audit v2.** Migration adding the nullable columns; record version 2 with user, token, project, session and address;
   `verify` handles v1 and v2; keyed chain and signed checkpoints for server mode behind a feature of the service. Test:
   old logs verify; truncating the tail is detected with a checkpoint; a v2 record with a changed `user_id` fails.
3. **`pm-accounts`: users, passwords, TOTP, sessions, throttling,** with its own migrations and `server.db`. No HTTP yet.
   Test: Argon2 parameter upgrade at login, constant behaviour for unknown users, TOTP replay refused, recovery codes
   single use, throttle back-off, session expiry and rotation.
4. **Server mode in `pm-api`.** `proxymind serve --accounts`: session middleware replacing the token guard when accounts
   are on, cookies, CSRF layers, `allowed_hosts`, the setup page and bootstrap, TLS (own certificate, behind proxy,
   self-signed with pinning), refusal to listen beyond loopback without TLS. Test: route matrix without a session is 401,
   cookie flags, CSRF cases (no header, wrong origin, `Sec-Fetch-Site`), fixation, `next=` handling, plain HTTP refused on
   a non-loopback address, pin mismatch fails.
5. **Tokens.** `pm3_` tokens for agents, CI and plugins, in both modes; `proxymind token …`; `proxymind login`; the MCP bridge
   to a server. Test: actor derived from the token, role ceiling and tier cap, expiry, revocation takes effect on the next
   request, a token cannot create tokens, tokens never appear in logs or audit detail.
6. **Roles and memberships (3.2).** Per-project roles, the matrix in this ADR enforced by `require`, the people-only set
   fixed for agents of owners, the ROE option `approvals.require_other_person`, per-user redactor with host binding (F-5),
   events filtered by membership. Test: the matrix test over every REST route and MCP tool for each role and for an
   unauthenticated client.
7. **Passkeys.** Decide the library or the in-house verifier (OpenSSL check first), enrolment, login, counter checks,
   recovery by link and by `reset-owner`. Test: WebAuthn vectors, a cloned authenticator is refused, host-name change
   behaviour documented.
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
