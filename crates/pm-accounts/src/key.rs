//! The server key: 32 random bytes in `<server home>/server.key`, from which HKDF-SHA256 derives one key per purpose.
//! Nothing but derived keys is used to protect data, so a leak of one purpose (say the audit chain's key handed to
//! `pm-service`) says nothing about the others. The master key never appears in `Debug`, logs or errors.

use std::io::{Read, Write};
use std::path::Path;

use ring::hkdf;

use crate::error::{AccountError, Result};
use crate::util::{hex, random, unhex};

/// What a derived key is for. The label is part of the HKDF `info`, so it must never change once released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// ChaCha20-Poly1305 key for TOTP secrets at rest.
    TotpEncryption,
    /// HMAC-SHA256 of session ids (and pending sign-in tokens).
    SessionId,
    /// HMAC-SHA256 of recovery codes.
    RecoveryCode,
    /// HMAC-SHA256 of one-time setup and invite tokens.
    OneTimeToken,
    /// HMAC-SHA256 of the claimed handle in the throttle table (so it holds no usernames).
    Throttle,
    /// The keyed audit chain: the security log here, and the project audit log through `pm_policy::HmacKey`.
    AuditChain,
    /// HMAC-SHA256 of `pm3_` API tokens (ADR-0022 step 5). Reserved so the label is fixed now.
    ApiToken,
    /// HMAC-SHA256 that makes the credential ids shown for a username that has no passkey (so asking for the
    /// sign-in options of a name does not reveal whether the name exists).
    PasskeyDecoy,
    /// ChaCha20-Poly1305 key for OIDC client secrets at rest (ADR-0022 step 8; the provider id is the associated data).
    OidcSecret,
}

impl KeyPurpose {
    fn label(self) -> &'static str {
        match self {
            KeyPurpose::TotpEncryption => "proxymind/v1/totp-encryption",
            KeyPurpose::SessionId => "proxymind/v1/session-id",
            KeyPurpose::RecoveryCode => "proxymind/v1/recovery-code",
            KeyPurpose::OneTimeToken => "proxymind/v1/one-time-token",
            KeyPurpose::Throttle => "proxymind/v1/throttle",
            KeyPurpose::AuditChain => "proxymind/v1/audit-chain",
            KeyPurpose::ApiToken => "proxymind/v1/api-token",
            KeyPurpose::PasskeyDecoy => "proxymind/v1/passkey-decoy",
            KeyPurpose::OidcSecret => "proxymind/v1/oidc-secret",
        }
    }
}

struct Len32;

impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// The master key.
pub struct ServerKey([u8; 32]);

impl std::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerKey([redacted])")
    }
}

impl ServerKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 64 hex digits (whitespace around them ignored), for `PROXYMIND_SERVER_KEY`.
    pub fn from_hex(text: &str) -> Result<Self> {
        let bytes = unhex(text.trim()).ok_or_else(|| AccountError::ServerKey("not hexadecimal".into()))?;
        let bytes: [u8; 32] =
            bytes.try_into().map_err(|_| AccountError::ServerKey("must be 32 bytes (64 hex digits)".into()))?;
        Ok(Self(bytes))
    }

    pub fn generate() -> Result<Self> {
        Ok(Self(random::<32>()?))
    }

    /// Loads `path`, or creates it (mode 0600 on Unix, hex text) when it does not exist. An existing file that other
    /// users can read is refused on Unix: fix the mode, and consider the key exposed.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::metadata(path) {
            Ok(_) => Self::load(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(dir)?;
                }
                let key = Self::generate()?;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(path) {
                    Ok(mut file) => {
                        file.write_all(hex(&key.0).as_bytes())?;
                        file.write_all(b"\n")?;
                        file.sync_all()?;
                        Ok(key)
                    }
                    // Lost a race with another process that created it first: use theirs.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Self::load(path),
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    fn load(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(AccountError::ServerKey(format!(
                    "{} is readable by other users (mode {:o}); chmod 600 it",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let mut text = String::new();
        std::fs::File::open(path)?.take(4096).read_to_string(&mut text)?;
        Self::from_hex(&text)
    }

    /// The 32-byte key for `purpose`.
    pub fn derive(&self, purpose: KeyPurpose) -> [u8; 32] {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"proxymind/server-key").extract(&self.0);
        let mut out = [0u8; 32];
        // Expanding 32 bytes from SHA-256 cannot exceed the HKDF limit, so these cannot fail.
        if let Ok(okm) = prk.expand(&[purpose.label().as_bytes()], Len32) {
            let _ = okm.fill(&mut out);
        }
        out
    }
}
