//! Plain data types returned by the API. None holds a secret.

use crate::error::{AccountError, Result};

/// A role in one project (ADR-0022, Roles). What each may do is `pm-service`'s table; this crate only stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Owner,
    Tester,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Tester => "tester",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "owner" => Ok(Role::Owner),
            "tester" => Ok(Role::Tester),
            "viewer" => Ok(Role::Viewer),
            _ => Err(AccountError::InvalidArgument("role must be owner, tester or viewer")),
        }
    }

    /// Higher is more powerful.
    pub fn rank(self) -> u8 {
        match self {
            Role::Owner => 3,
            Role::Tester => 2,
            Role::Viewer => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Active,
    Disabled,
}

impl UserStatus {
    pub(crate) fn parse(s: &str) -> Self {
        if s == "active" { UserStatus::Active } else { UserStatus::Disabled }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Stable id, `u_` plus 32 hex digits. Never reused, kept in the audit log after the account is disabled.
    pub id: String,
    /// Normalised handle (lower case, ASCII). Unique.
    pub username: String,
    pub display_name: String,
    pub status: UserStatus,
    /// Manages accounts and server settings; has no project access by itself.
    pub server_admin: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub project_id: String,
    pub user_id: String,
    pub role: Role,
    pub created_at: i64,
    pub created_by: Option<String>,
}

/// What the server knows about the client, kept as hints (never as proof of anything).
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub addr: Option<String>,
    pub user_agent: Option<String>,
}

impl ClientInfo {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: Some(addr.into()), user_agent: None }
    }
}

/// A session id, shown once. The server keeps only its HMAC.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: crate::Secret,
    /// Safe to log and to show: the first 8 bytes of the stored hash, in hex (ADR-0022, audit `session_id`).
    pub reference: String,
    pub user_id: String,
    pub created_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub reference: String,
    pub user_id: String,
    /// `password`, `password+totp`, `password+recovery`.
    pub auth_method: String,
    pub created_at: i64,
    /// When the person last proved who they are (kept across rotation); for "fresh login" checks.
    pub authenticated_at: i64,
    pub last_seen_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
    pub client_addr: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoginSuccess {
    pub user: User,
    pub session: NewSession,
}

/// The result of the password step.
#[derive(Debug, Clone)]
pub enum LoginStep {
    Authenticated(Box<LoginSuccess>),
    /// A TOTP code or a recovery code is needed: call `login_second_factor` with this token.
    SecondFactorRequired {
        pending: crate::Secret,
        expires_at: i64,
    },
    /// This account must have a second factor and has none: call `begin_totp_enrolment_pending` and
    /// `finish_enrolment` with this token.
    EnrolmentRequired {
        pending: crate::Secret,
        expires_at: i64,
    },
}

#[derive(Clone)]
pub struct TotpEnrolment {
    /// Base32, for typing into an authenticator app.
    pub secret_base32: String,
    /// `otpauth://` URI for a QR code.
    pub otpauth_uri: String,
}

impl std::fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpEnrolment([redacted])")
    }
}

#[derive(Debug, Clone)]
pub struct SetupToken {
    pub token: crate::Secret,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewInvite {
    pub id: String,
    pub token: crate::Secret,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    pub id: String,
    pub role: Role,
    pub project_id: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    pub seq: i64,
    pub at: i64,
    pub kind: String,
    pub user_id: Option<String>,
    pub actor: String,
    pub client_addr: Option<String>,
    pub detail: String,
}
