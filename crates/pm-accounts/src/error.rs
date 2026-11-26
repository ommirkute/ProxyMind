//! One error type. Variants that an unauthenticated caller can reach say as little as possible: a wrong password, an
//! unknown or disabled user and a wrong second factor are all [`AccountError::InvalidCredentials`].

use std::time::Duration;

pub type Result<T, E = AccountError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// Wrong password or code, unknown user, disabled user: deliberately the same.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Too many recent failures for this account or address. Not a lock: the delay grows and then expires.
    #[error("too many attempts, try again in {} s", .retry_after.as_secs())]
    Throttled { retry_after: Duration },
    /// The pending sign-in token is unknown, expired, used up or of the wrong kind.
    #[error("this sign-in step has expired or is not valid")]
    InvalidPending,
    /// A code was wrong where the caller is already authenticated (enrolment, confirmation).
    #[error("invalid code")]
    InvalidCode,
    #[error("invalid or expired invite")]
    InvalidInvite,
    #[error("invalid or expired setup token")]
    InvalidSetupToken,
    #[error("an owner already exists")]
    OwnerExists,
    #[error("session is not valid")]
    SessionInvalid,
    #[error("password refused: {0}")]
    WeakPassword(&'static str),
    #[error("invalid username: {0}")]
    InvalidUsername(&'static str),
    #[error("that username is taken")]
    UsernameTaken,
    #[error("no such user")]
    NoSuchUser,
    /// The acting user may not do this (not a server admin, not an owner of the project).
    #[error("not authorised")]
    NotAuthorised,
    #[error("this would leave the server without an active administrator")]
    LastAdmin,
    #[error("this would leave the project without an owner")]
    LastOwner,
    #[error("this account must keep a second factor")]
    SecondFactorRequired,
    #[error("a second factor is already enrolled; remove it first")]
    AlreadyEnrolled,
    #[error("no pending second-factor enrolment")]
    NotEnrolling,
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// A passkey ceremony the signed-in or enrolling person started was refused (the reason is a fixed phrase).
    #[error("passkey refused: {0}")]
    PasskeyRefused(&'static str),
    /// The account signs in with a passkey (it has one, and the server or the account allows nothing weaker).
    #[error("this account signs in with a passkey: use \"Sign in with a passkey\"")]
    PasskeyRequired,
    /// The last passkey of an account cannot be removed: the server requires one, or nothing else would let the
    /// account sign in.
    #[error("this is the last way to sign in to this account; add another passkey, or an authenticator, first")]
    LastPasskey,
    #[error("no such passkey")]
    NoSuchPasskey,
    #[error("invalid or expired enrolment link")]
    InvalidEnrolmentLink,
    /// A presented `pm3_` token is unknown, revoked, expired, or its owner is disabled or no longer a member:
    /// deliberately the same for all of them (the security log says which).
    #[error("the token is not valid")]
    InvalidToken,
    #[error("a live token already has that name: pick another or revoke it")]
    TokenNameTaken,
    #[error("no such token")]
    NoSuchToken,
    #[error("too many live tokens for this user: revoke some first")]
    TooManyTokens,
    /// The single-user token file or its key cannot be used (readable by others, damaged, locked).
    #[error("token file: {0}")]
    TokenStore(String),
    #[error("server key: {0}")]
    ServerKey(String),
    #[error("a stored secret could not be decrypted (wrong server key, or the record was moved)")]
    Decrypt,
    #[error("the account database was created by a newer ProxyMind (schema {0})")]
    NewerSchema(i64),
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal error: {0}")]
    Internal(String),
}
