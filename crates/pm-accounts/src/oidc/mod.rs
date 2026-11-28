//! Signing in with an OpenID Connect provider (ADR-0022 step 8): the second identity source, after local accounts.
//!
//! This module is **pure and local**: it holds no HTTP client. `pm-api` fetches the discovery document, the key set and
//! the token, and hands the bytes here; everything that decides something lives here, where it can be tested without a
//! network. (A fetcher injected into this crate would have to be async, and this crate is not.)
//!
//! * [`discovery`]: the discovery document, PKCE, the authorization URL, the RFC 9207 `iss` check.
//! * [`jwt`]: JWKS and ID-token verification with ring (RS256, ES256, EdDSA; never `none`, never `HS*`).
//! * [`providers`]: the configured providers, client secrets sealed under the OIDC key.
//! * `flow`: the sign-in itself: single-use state, identity mapping, linking, provisioning, group claims.
//!
//! **Identity** is the pair `(iss, sub)`, stored as the `external_id` of a `credentials` row of kind `oidc`
//! (`iss`, a newline, `sub`). Email and name are display data only.
//!
//! **Owners and claims.** A claim can grant `tester` or `viewer`, never `owner`, never server administrator (the
//! mapping cannot even be written). An account that is a server administrator or an owner of a project can sign in with
//! OIDC only if it has a local way in of its own (a passkey, or a password with an authenticator): the owner role never
//! depends on the provider, and the local credential is the break-glass path. Claims leave such accounts alone, and
//! linking by email never applies to them.

pub mod discovery;
mod flow;
pub mod jwt;
mod providers;

pub use flow::{
    BeginPurpose, MAX_PENDING, OidcBegin, OidcIdentity, OidcOutcome, OidcPendingInfo, PENDING_TTL, PendingPurpose,
    PendingStore,
};
pub use providers::{OidcProvider, ProviderInput, RoleMapping, SecretChange};
