//! Accounts of ProxyMind's own users (ADR-0022, step 3): who they are, how they prove it, and the sessions that follow.
//!
//! This crate has **no HTTP and no knowledge of projects beyond ids**. `pm-api` (step 4) turns requests into calls
//! here; `pm-service` (step 6) turns a validated session into a `Principal`. It depends on neither, nor on any other
//! ProxyMind crate. Accounts are *not* the test identities of `pm-identity`.
//!
//! * **Storage:** `server.db` (SQLite, WAL, append-only migrations), separate from every project file.
//! * **Server key:** [`ServerKey`], 32 bytes in `server.key`; HKDF-SHA256 derives a key per [`KeyPurpose`].
//! * **Passwords:** Argon2id PHC strings, upgraded at login when the stored cost is below the current one.
//!   Unknown users cost the same: a dummy hash is verified and the failure looks identical.
//! * **Second factor:** TOTP (RFC 6238; secret encrypted with ChaCha20-Poly1305, user id as associated data, a used
//!   step is never accepted twice) or a single-use recovery code. Owners, server admins and testers must have one
//!   (viewers too unless [`Config::allow_password_only_viewers`]); a passkey is a complete sign-in of its own and
//!   counts as the second factor.
//! * **Passkeys (step 7):** WebAuthn verified in-house with ring (`webauthn`: a strict CBOR decoder, COSE keys, the
//!   checks of the specification), stored in `credentials`; single-use five-minute challenges; a sign counter that must
//!   not go backwards; recovery by a one-time enrolment link; a server setting that requires them (`passkeys`).
//! * **OIDC (step 8):** sign in with an OpenID Connect provider (`oidc`): discovery, PKCE, ID-token verification with
//!   ring, identities as `(iss, sub)`, linking, auto-create and group claims; the HTTP itself is `pm-api`'s.
//! * **Sessions:** random 256-bit ids returned once, stored as HMAC-SHA256; idle 8 h and absolute 7 d by default;
//!   rotation invalidates the old id; revocation takes effect at the next validation.
//! * **Throttling:** per account (by the claimed handle, so unknown names are throttled the same) and per address,
//!   with exponential back-off; never a permanent lock.
//! * **Invite only:** an account is created by accepting an invite, or by bootstrapping the first owner with a
//!   one-time setup token. `reset_owner` (local console) is the recovery path.
//! * **Tokens:** `pm3_<kind>_<256 bits>` for agents, CI and plugins; stored as HMAC-SHA256, shown once, with an owner,
//!   a role ceiling, a tier cap and an expiry (`token`, the shared rules; `tokens`, `server.db`; `token_file`, the
//!   single-user file `<home>/tokens.json`).
//! * **Security log:** every account event goes to an append-only, HMAC-chained table; never a secret.
//!
//! Everything here trusts its caller to have authenticated *the caller*: functions that act on behalf of a user
//! (`create_invite`, `set_membership`, …) take the acting user's id and check what they can, but deciding who the
//! acting user is belongs to the layer above.

mod audit;
mod clock;
mod error;
mod key;
mod login;
mod migrations;
mod model;
pub mod oidc;
mod passkeys;
mod password;
mod sessions;
mod store;
mod throttle;
mod token;
mod token_file;
mod tokens;
mod totp;
mod users;
mod util;
pub mod webauthn;

#[cfg(test)]
mod oidc_tests;
#[cfg(test)]
mod passkey_tests;
#[cfg(test)]
mod tests;

pub use clock::{Clock, ManualClock, SystemClock};
pub use error::{AccountError, Result};
pub use key::{KeyPurpose, ServerKey};
pub use model::{
    ClientInfo, InviteInfo, LoginStep, LoginSuccess, Membership, NewInvite, NewSession, Role, SecurityEvent,
    SessionInfo, SetupToken, TotpEnrolment, User, UserStatus,
};
pub use passkeys::{
    AssertionResponse, EnrolmentTarget, MAX_PASSKEYS, NewEnrolmentLink, PasskeyInfo, RegistrationResponse,
    counter_allows, user_handle,
};
pub use password::{Argon2Cost, check_policy as check_password_policy};
pub use store::{Accounts, Config};
pub use throttle::ThrottleConfig;
pub use token::{
    DEFAULT_TTL, MAX_TTL, MIN_TTL, NewToken, NewTokenSpec, TIER_NAMES, TOKEN_PREFIX, TokenAuth, TokenInfo, TokenKind,
    effective_role, effective_tier_cap, generate as generate_token, parse_ttl, shape as token_shape,
    validate_name as validate_token_name, validate_tier_cap,
};
pub use token_file::TokenFile;
pub use tokens::CONSOLE;
pub use totp::{hotp, totp};
pub use util::Secret;
