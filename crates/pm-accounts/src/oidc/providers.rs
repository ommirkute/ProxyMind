//! Provider configuration (server administrators only; the API asks for a fresh sign-in): create, change, delete,
//! list. The client secret is sealed with ChaCha20-Poly1305 under the OIDC key (the provider id as associated data),
//! is never part of [`OidcProvider`], and is read back only by [`Accounts::oidc_client_secret`] for the token request.

use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::Value;

use super::discovery::check_issuer;
use crate::error::{AccountError, Result};
use crate::model::Role;
use crate::store::Accounts;
use crate::users::new_id;
use crate::util::{Secret, clip};

/// A group claim value mapped to a role on the served project. Only `tester` and `viewer` exist here: a claim can
/// never grant `owner` (or make anyone a server administrator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleMapping {
    pub value: String,
    pub role: Role,
}

/// A configured provider. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProvider {
    pub id: String,
    /// Shown on the sign-in button.
    pub name: String,
    /// Exactly the `iss` the provider uses (and its discovery document says).
    pub issuer: String,
    pub client_id: String,
    /// A client secret is stored (a public client has none).
    pub has_secret: bool,
    /// Scopes besides `openid`.
    pub scopes: Vec<String>,
    /// The claim that lists the user's groups, if roles come from the provider.
    pub group_claim: Option<String>,
    pub role_map: Vec<RoleMapping>,
    /// Lower-case domains whose verified emails may create an account (viewer). Empty: nobody (the default).
    pub auto_create_domains: Vec<String>,
    /// Link an existing local account whose handle is the verified email. Off by default.
    pub email_linking: bool,
    /// The token's `acr` must be one of these (when not empty).
    pub required_acr: Vec<String>,
    /// The token's `amr` must contain all of these.
    pub required_amr: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// What to do with the stored client secret.
#[derive(Clone)]
pub enum SecretChange {
    Keep,
    Clear,
    Set(Secret),
}

impl std::fmt::Debug for SecretChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SecretChange::Keep => "Keep",
            SecretChange::Clear => "Clear",
            SecretChange::Set(_) => "Set([redacted])",
        })
    }
}

/// What an administrator enters.
#[derive(Debug, Clone)]
pub struct ProviderInput {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretChange,
    pub scopes: Vec<String>,
    pub group_claim: Option<String>,
    pub role_map: Vec<RoleMapping>,
    pub auto_create_domains: Vec<String>,
    pub email_linking: bool,
    pub required_acr: Vec<String>,
    pub required_amr: Vec<String>,
    pub enabled: bool,
}

const COLS: &str = "id, name, issuer, client_id, client_secret IS NOT NULL, scopes, group_claim, role_map, \
                    auto_create_domains, email_linking, required_acr, required_amr, enabled, created_at, updated_at";

fn list_of(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn from_row(r: &Row<'_>) -> rusqlite::Result<OidcProvider> {
    let role_map: Vec<(String, String)> = serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default();
    Ok(OidcProvider {
        id: r.get(0)?,
        name: r.get(1)?,
        issuer: r.get(2)?,
        client_id: r.get(3)?,
        has_secret: r.get(4)?,
        scopes: list_of(&r.get::<_, String>(5)?),
        group_claim: r.get(6)?,
        role_map: role_map
            .into_iter()
            .filter_map(|(value, role)| {
                // A stored `owner` (never written by this code) is dropped, not honoured.
                let role = Role::parse(&role).ok().filter(|r| *r != Role::Owner)?;
                Some(RoleMapping { value, role })
            })
            .collect(),
        auto_create_domains: list_of(&r.get::<_, String>(8)?),
        email_linking: r.get(9)?,
        required_acr: list_of(&r.get::<_, String>(10)?),
        required_amr: list_of(&r.get::<_, String>(11)?),
        enabled: r.get(12)?,
        created_at: r.get(13)?,
        updated_at: r.get(14)?,
    })
}

pub(crate) fn find_provider(conn: &Connection, id: &str) -> Result<Option<OidcProvider>> {
    Ok(conn.query_row(&format!("SELECT {COLS} FROM oidc_providers WHERE id = ?1"), [id], from_row).optional()?)
}

fn aad(id: &str) -> Vec<u8> {
    format!("proxymind/oidc-secret/v1/{id}").into_bytes()
}

fn invalid<T>(why: &'static str) -> Result<T> {
    Err(AccountError::InvalidArgument(why))
}

fn token_chars(s: &str, extra: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// Checks every field; returns the cleaned input.
fn validate(mut i: ProviderInput) -> Result<ProviderInput> {
    i.name = i.name.trim().to_string();
    if i.name.is_empty() || i.name.chars().count() > 80 || i.name.chars().any(char::is_control) {
        return invalid("the display name must be 1 to 80 characters");
    }
    i.issuer = i.issuer.trim().to_string();
    if let Err(why) = check_issuer(&i.issuer) {
        // `why` is a static string from the checker.
        return Err(AccountError::InvalidArgument(why));
    }
    i.client_id = i.client_id.trim().to_string();
    if i.client_id.is_empty() || i.client_id.len() > 256 || i.client_id.chars().any(|c| c.is_control() || c == ' ') {
        return invalid("the client id must be 1 to 256 characters without spaces");
    }
    if let SecretChange::Set(s) = &i.client_secret
        && (s.expose().is_empty() || s.expose().len() > 1024 || s.expose().chars().any(char::is_control))
    {
        return invalid("the client secret must be 1 to 1024 characters");
    }
    if i.scopes.len() > 20 || !i.scopes.iter().all(|s| s.len() <= 64 && token_chars(s, "._:/-")) {
        return invalid("scopes: up to 20, each of letters, digits and . _ : / -");
    }
    i.scopes.retain(|s| s != "openid");
    i.scopes.dedup();
    i.group_claim = i.group_claim.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    if let Some(c) = &i.group_claim
        && (c.len() > 64 || !token_chars(c, "._:/@-"))
    {
        return invalid("the group claim is a claim name of letters, digits and . _ : / @ -");
    }
    if i.role_map.len() > 50 {
        return invalid("at most 50 group mappings");
    }
    for m in &i.role_map {
        if m.role == Role::Owner {
            return invalid("a group may map to tester or viewer only: a claim never grants owner");
        }
        if m.value.is_empty() || m.value.len() > 256 || m.value.chars().any(char::is_control) {
            return invalid("a group value must be 1 to 256 characters");
        }
    }
    if !i.role_map.is_empty() && i.group_claim.is_none() {
        return invalid("group mappings need a group claim name");
    }
    i.auto_create_domains = i.auto_create_domains.into_iter().map(|d| d.trim().to_ascii_lowercase()).collect();
    if i.auto_create_domains.len() > 20
        || !i.auto_create_domains.iter().all(|d| {
            d.len() <= 253
                && d.contains('.')
                && token_chars(d, ".-")
                && !d.starts_with(['.', '-'])
                && !d.ends_with(['.', '-'])
        })
    {
        return invalid("auto-create domains: up to 20 exact domains such as example.com (no @, no wildcards)");
    }
    for list in [&i.required_acr, &i.required_amr] {
        if list.len() > 10 || !list.iter().all(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
        {
            return invalid("acr and amr requirements: up to 10 values each");
        }
    }
    Ok(i)
}

fn json_list(v: &[String]) -> String {
    Value::from(v.to_vec()).to_string()
}

fn json_roles(m: &[RoleMapping]) -> String {
    Value::from(m.iter().map(|m| Value::from(vec![m.value.clone(), m.role.as_str().to_string()])).collect::<Vec<_>>())
        .to_string()
}

impl Accounts {
    /// Every provider (administrators' view).
    pub fn oidc_providers(&self) -> Result<Vec<OidcProvider>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM oidc_providers ORDER BY created_at, id"))?;
        let rows = stmt.query_map([], from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// One provider, enabled or not.
    pub fn oidc_provider(&self, id: &str) -> Result<Option<OidcProvider>> {
        find_provider(&self.conn(), id)
    }

    /// What the sign-in page lists: id and display name of every enabled provider. Nothing else.
    pub fn oidc_public_providers(&self) -> Result<Vec<(String, String)>> {
        Ok(self.oidc_providers()?.into_iter().filter(|p| p.enabled).map(|p| (p.id, p.name)).collect())
    }

    /// The client secret, for the token request only. `None` for a public client.
    pub fn oidc_client_secret(&self, provider_id: &str) -> Result<Option<Secret>> {
        let sealed: Option<Option<Vec<u8>>> = self
            .conn()
            .query_row("SELECT client_secret FROM oidc_providers WHERE id = ?1", [provider_id], |r| r.get(0))
            .optional()?;
        let sealed = sealed.ok_or(AccountError::NoSuchProvider)?;
        match sealed {
            None => Ok(None),
            Some(blob) => {
                let plain = self.open_oidc(&blob, &aad(provider_id))?;
                Ok(Some(Secret(String::from_utf8(plain).map_err(|_| AccountError::Decrypt)?)))
            }
        }
    }

    /// Adds a provider. Only an active server administrator. The issuer is unique across providers (an identity is
    /// `(iss, sub)`, so two providers with one issuer would share identities).
    pub fn oidc_provider_create(&self, acting: &str, input: ProviderInput) -> Result<OidcProvider> {
        let i = validate(input)?;
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            let id = format!("op_{}", &new_id("")?[..16]);
            let sealed = match &i.client_secret {
                SecretChange::Set(s) => Some(self.seal_oidc(s.expose().as_bytes(), &aad(&id))?),
                _ => None,
            };
            let now = self.now();
            tx.execute(
                "INSERT INTO oidc_providers (id, name, issuer, client_id, client_secret, scopes, group_claim, role_map, \
                 auto_create_domains, email_linking, required_acr, required_amr, enabled, created_at, updated_at, \
                 updated_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14, ?15)",
                rusqlite::params![
                    id,
                    i.name,
                    i.issuer,
                    i.client_id,
                    sealed,
                    json_list(&i.scopes),
                    i.group_claim,
                    json_roles(&i.role_map),
                    json_list(&i.auto_create_domains),
                    i.email_linking,
                    json_list(&i.required_acr),
                    json_list(&i.required_amr),
                    i.enabled,
                    now,
                    acting
                ],
            )
            .map_err(provider_conflict)?;
            self.audit(tx, "oidc_provider_created", Some(acting), &format!("user:{acting}"), None, &id)?;
            find_provider(tx, &id)?.ok_or_else(|| AccountError::Internal("provider vanished".into()))
        })
    }

    /// Changes a provider (all fields; the secret as `input.client_secret` says).
    pub fn oidc_provider_update(&self, acting: &str, id: &str, input: ProviderInput) -> Result<OidcProvider> {
        let i = validate(input)?;
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            let old = find_provider(tx, id)?.ok_or(AccountError::NoSuchProvider)?;
            let now = self.now();
            tx.execute(
                "UPDATE oidc_providers SET name = ?2, issuer = ?3, client_id = ?4, scopes = ?5, group_claim = ?6, \
                 role_map = ?7, auto_create_domains = ?8, email_linking = ?9, required_acr = ?10, required_amr = ?11, \
                 enabled = ?12, updated_at = ?13, updated_by = ?14 WHERE id = ?1",
                rusqlite::params![
                    id,
                    i.name,
                    i.issuer,
                    i.client_id,
                    json_list(&i.scopes),
                    i.group_claim,
                    json_roles(&i.role_map),
                    json_list(&i.auto_create_domains),
                    i.email_linking,
                    json_list(&i.required_acr),
                    json_list(&i.required_amr),
                    i.enabled,
                    now,
                    acting
                ],
            )
            .map_err(provider_conflict)?;
            match &i.client_secret {
                SecretChange::Keep => {}
                SecretChange::Clear => {
                    tx.execute("UPDATE oidc_providers SET client_secret = NULL WHERE id = ?1", [id])?;
                }
                SecretChange::Set(s) => {
                    let sealed = self.seal_oidc(s.expose().as_bytes(), &aad(id))?;
                    tx.execute(
                        "UPDATE oidc_providers SET client_secret = ?2 WHERE id = ?1",
                        rusqlite::params![id, sealed],
                    )?;
                }
            }
            // The issuer is the identity namespace: changing it would silently re-point every linked identity.
            if old.issuer != i.issuer {
                let n = tx.execute(
                    "DELETE FROM credentials WHERE kind = 'oidc' AND json_extract(meta, '$.provider') = ?1",
                    [id],
                )?;
                self.audit(
                    tx,
                    "oidc_identities_unlinked",
                    Some(acting),
                    &format!("user:{acting}"),
                    None,
                    &format!("{id} {n} (issuer changed)"),
                )?;
            }
            // What changed, in words that hold no value.
            let mut what = Vec::new();
            for (changed, name) in [
                (
                    old.email_linking != i.email_linking,
                    if i.email_linking { "email linking on" } else { "email linking off" },
                ),
                (old.auto_create_domains != i.auto_create_domains, "auto-create domains"),
                (old.role_map != i.role_map || old.group_claim != i.group_claim, "group mapping"),
                (old.issuer != i.issuer, "issuer"),
                (old.client_id != i.client_id, "client id"),
                (old.enabled != i.enabled, if i.enabled { "enabled" } else { "disabled" }),
                (!matches!(i.client_secret, SecretChange::Keep), "client secret"),
            ] {
                if changed {
                    what.push(name);
                }
            }
            self.audit(
                tx,
                "oidc_provider_updated",
                Some(acting),
                &format!("user:{acting}"),
                None,
                &format!("{id}: {}", clip(&what.join(", "), 150)),
            )?;
            find_provider(tx, id)?.ok_or(AccountError::NoSuchProvider)
        })
    }

    /// Deletes a provider and the identities linked through it (a person who signed in only that way needs an
    /// enrolment link afterwards).
    pub fn oidc_provider_delete(&self, acting: &str, id: &str) -> Result<()> {
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            find_provider(tx, id)?.ok_or(AccountError::NoSuchProvider)?;
            let n = tx.execute(
                "DELETE FROM credentials WHERE kind = 'oidc' AND json_extract(meta, '$.provider') = ?1",
                [id],
            )?;
            tx.execute("DELETE FROM oidc_providers WHERE id = ?1", [id])?;
            self.audit(
                tx,
                "oidc_provider_deleted",
                Some(acting),
                &format!("user:{acting}"),
                None,
                &format!("{id}, {n} identities unlinked"),
            )
        })
    }

    /// Writes a security-log entry for something an administrator did with a provider that changes nothing stored
    /// (the discovery test).
    pub fn oidc_provider_tested(&self, acting: &str, id: &str, ok: bool) -> Result<()> {
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            self.audit(
                tx,
                "oidc_provider_tested",
                Some(acting),
                &format!("user:{acting}"),
                None,
                &format!("{id} {}", if ok { "ok" } else { "failed" }),
            )
        })
    }
}

fn provider_conflict(e: rusqlite::Error) -> AccountError {
    match e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
            AccountError::InvalidArgument("another provider already uses this issuer")
        }
        other => other.into(),
    }
}
