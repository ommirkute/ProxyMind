//! Test identities: capture from history, check, log in again, list.

use pm_identity::{ANONYMOUS, Identity};
use pm_policy::{Actor, ActorKind, Tier};
use pm_store::IdentityRow;
use serde::Serialize;
use serde_json::json;

use crate::replay::parse_url_endpoint;
use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// What anyone (including agents) may see about an identity: names, never values.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityInfo {
    pub name: String,
    pub role: String,
    pub status: String,
    pub cookies: Vec<String>,
    pub headers: Vec<String>,
    pub has_health_check: bool,
    pub has_login: bool,
    /// Whether a learned logged-out signature is set.
    pub logged_out: bool,
    /// Steps in the login recipe.
    pub login_steps: usize,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityCheck {
    pub name: String,
    /// ok, logged_out, or unknown (no health check configured)
    pub status: String,
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_id: Option<i64>,
}

fn info(row: &IdentityRow) -> IdentityInfo {
    let ident: Identity = serde_json::from_str(&row.data).unwrap_or_else(|_| Identity::anonymous());
    IdentityInfo {
        name: row.name.clone(),
        role: row.role.clone(),
        status: row.status.clone(),
        cookies: ident.auth.cookies.iter().map(|(k, _)| k.clone()).collect(),
        headers: ident.auth.headers.iter().map(|(k, _)| k.clone()).collect(),
        has_health_check: ident.health.is_some(),
        has_login: ident.login.is_some(),
        logged_out: ident.logged_out.is_some(),
        login_steps: ident.login.as_ref().map_or(0, |l| l.steps.len()),
        created_by: row.created_by.clone(),
    }
}

impl Service {
    pub(crate) fn load_identity(&self, name: &str) -> Result<Identity> {
        if name == ANONYMOUS {
            return Ok(Identity::anonymous());
        }
        let row = self
            .store
            .read(|db| db.get_identity(name))?
            .ok_or_else(|| ServiceError::NotFound(format!("identity {name}")))?;
        serde_json::from_str(&row.data).map_err(|e| ServiceError::Invalid(format!("identity {name} is corrupt: {e}")))
    }

    pub(crate) fn save_identity(&self, ident: &Identity, created_by: &str, status: &str) -> Result<()> {
        let row = IdentityRow {
            name: ident.name.clone(),
            role: ident.role.clone(),
            data: serde_json::to_string(ident).map_err(|e| ServiceError::Invalid(e.to_string()))?,
            created_by: created_by.into(),
            status: status.into(),
            updated_ms: now_ms(),
        };
        self.store.write(|db| db.upsert_identity(&row))?;
        Ok(())
    }

    pub fn identity_list(&self) -> Result<Vec<IdentityInfo>> {
        Ok(self.store.read(|db| db.list_identities())?.iter().map(info).collect())
    }

    /// Creates or replaces an identity from a full definition. Humans only,
    /// because it handles real credentials.
    pub fn identity_set(&self, actor: &Actor, ident: Identity) -> Result<IdentityInfo> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can define identities with credentials".into()));
        }
        if !pm_identity::valid_name(&ident.name) || ident.name == ANONYMOUS {
            return Err(ServiceError::Invalid(format!("bad identity name {:?}", ident.name)));
        }
        self.save_identity(&ident, &actor.id(), "unknown")?;
        self.audit(&actor.id(), "identity_set", json!({ "name": ident.name, "role": ident.role }), "allow")?;
        Ok(info(
            &self
                .store
                .read(|db| db.get_identity(&ident.name))?
                .ok_or_else(|| ServiceError::NotFound(ident.name.clone()))?,
        ))
    }

    /// Creates an identity from the credentials in a recorded request (its
    /// cookies and auth headers). Agents may do this: they never see the values.
    pub fn identity_capture(&self, actor: &Actor, name: &str, role: &str, exchange_id: i64) -> Result<IdentityInfo> {
        if !pm_identity::valid_name(name) || name == ANONYMOUS {
            return Err(ServiceError::Invalid(format!("bad identity name {name:?}")));
        }
        let ex = self
            .store
            .read(|db| db.get_exchange(exchange_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {exchange_id}")))?;
        let auth = pm_identity::auth_from_request(&ex.request);
        if auth.is_empty() {
            return Err(ServiceError::Invalid(format!("exchange {exchange_id} carries no cookies or auth headers")));
        }
        // Keep an existing health check / login recipe if re-capturing.
        let (health, login, created_by) = match self.load_identity(name) {
            Ok(old) => (old.health, old.login, self.store.read(|db| db.get_identity(name))?.map(|r| r.created_by)),
            Err(_) => (None, None, None),
        };
        let ident = Identity { name: name.into(), role: role.into(), auth, health, login, logged_out: None };
        let created_by = created_by.unwrap_or_else(|| actor.id());
        self.save_identity(&ident, &created_by, "unknown")?;
        self.audit(
            &actor.id(),
            "identity_capture",
            json!({ "name": name, "role": role, "from_exchange": exchange_id }),
            "allow",
        )?;
        Ok(info(&self.store.read(|db| db.get_identity(name))?.ok_or_else(|| ServiceError::NotFound(name.into()))?))
    }

    fn exchange_url_and_raw(&self, exchange_id: i64) -> Result<(String, String, String)> {
        let ex = self
            .store
            .read(|db| db.get_exchange(exchange_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {exchange_id}")))?;
        let s = &ex.summary;
        let url = pm_core::url(&s.scheme, &s.host, s.port, "");
        Ok((url, String::from_utf8_lossy(&ex.request).into_owned(), s.method.clone()))
    }

    /// Uses a recorded GET (e.g. /api/me) as the identity's health check.
    pub fn identity_set_health_from(
        &self,
        actor: &Actor,
        name: &str,
        exchange_id: i64,
        expect_contains: Option<String>,
        expect_status: Option<u16>,
    ) -> Result<IdentityInfo> {
        let (url, raw, method) = self.exchange_url_and_raw(exchange_id)?;
        if Tier::for_http_method(&method) != Tier::ActiveSafe {
            return Err(ServiceError::Invalid("health checks must use GET, HEAD or OPTIONS".into()));
        }
        let mut ident = self.load_identity(name)?;
        ident.health = Some(pm_identity::HealthCheck { url, request: raw, expect_status, expect_contains });
        let created_by =
            self.store.read(|db| db.get_identity(name))?.map(|r| r.created_by).unwrap_or_else(|| actor.id());
        self.save_identity(&ident, &created_by, "unknown")?;
        self.audit(&actor.id(), "identity_set_health", json!({ "name": name, "from_exchange": exchange_id }), "allow")?;
        Ok(info(&self.store.read(|db| db.get_identity(name))?.ok_or_else(|| ServiceError::NotFound(name.into()))?))
    }

    /// Uses a recorded login request as the identity's login recipe. Humans
    /// only: the request contains the password.
    pub fn identity_set_login_from(
        &self,
        actor: &Actor,
        name: &str,
        exchange_id: i64,
        token_json_pointer: Option<String>,
    ) -> Result<IdentityInfo> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can set login recipes (they contain passwords)".into()));
        }
        let (url, raw, _) = self.exchange_url_and_raw(exchange_id)?;
        let mut ident = self.load_identity(name)?;
        ident.login = Some(pm_identity::LoginRecipe {
            steps: vec![pm_identity::LoginStep {
                url,
                request: raw,
                token_json_pointer,
                token_header: None,
                token_prefix: None,
                ..Default::default()
            }],
        });
        self.save_identity(&ident, &actor.id(), "unknown")?;
        self.audit(&actor.id(), "identity_set_login", json!({ "name": name, "from_exchange": exchange_id }), "allow")?;
        Ok(info(&self.store.read(|db| db.get_identity(name))?.ok_or_else(|| ServiceError::NotFound(name.into()))?))
    }

    pub fn identity_delete(&self, actor: &Actor, name: &str) -> Result<bool> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can delete identities".into()));
        }
        let deleted = self.store.write(|db| db.delete_identity(name))?;
        self.audit(&actor.id(), "identity_delete", json!({ "name": name }), if deleted { "allow" } else { "noop" })?;
        Ok(deleted)
    }

    /// Runs the identity's login recipe. Each step is checked by the policy
    /// gate as the human who set the identity up (they provided the
    /// credentials and the recipe), so agents don't need approval to keep a
    /// session alive. Returns what was learned.
    pub async fn identity_login(&self, name: &str) -> Result<Vec<String>> {
        let mut ident = self.load_identity(name)?;
        let recipe = ident.login.clone().ok_or_else(|| ServiceError::Invalid(format!("{name} has no login recipe")))?;
        let created_by = self.store.read(|db| db.get_identity(name))?.map(|r| r.created_by).unwrap_or_default();
        let owner = Actor::parse(&created_by).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let mut learned = Vec::new();
        // What this run has learned: cookies set by its steps (sent on to
        // later steps) and values read from responses.
        let mut run = pm_identity::AuthMaterial::default();
        let mut vars = std::collections::HashMap::new();
        for (i, step) in recipe.steps.iter().enumerate() {
            let raw = crate::session::substitute(&step.request, &vars);
            let out = self.outgoing(parse_url_endpoint(&step.url)?, raw.as_bytes(), true)?;
            match self.gate_send(&owner, "identity_login", &out, None, true, None)? {
                Authorization::Allowed { .. } => {}
                other => return Err(ServiceError::Invalid(format!("login step {} not allowed: {other:?}", i + 1))),
            }
            let wire = crate::session::set_cookies(&self.redactor.unredact(&out.raw), &run.cookies);
            let sent = self.transmit(&owner, &out, wire, None, true, "login").await?;
            let resp = sent.response.ok_or_else(|| {
                ServiceError::Invalid(format!("login step {} failed: {}", i + 1, sent.error.unwrap_or_default()))
            })?;
            learned.extend(step.absorb(&mut run, &resp));
            for x in &step.extract {
                // Target content: a line break would let it add to the next request.
                match x.find(&resp).filter(|v| crate::session::header_safe(v)) {
                    Some(v) => {
                        vars.insert(x.name.clone(), v);
                    }
                    None => learned.push(format!("step {}: {} not found", i + 1, x.name)),
                }
            }
        }
        for step in &recipe.steps {
            for (h, template) in &step.set_headers {
                let value = crate::session::substitute(template, &vars);
                if value.contains("{{") {
                    continue; // a value the run didn't find: keep the old one
                }
                run.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(h));
                run.headers.push((h.clone(), value));
                learned.push(format!("{h} header"));
            }
        }
        for (k, v) in run.cookies {
            ident.auth.cookies.retain(|(n, _)| n != &k);
            ident.auth.cookies.push((k, v));
        }
        for (h, v) in run.headers {
            ident.auth.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&h));
            ident.auth.headers.push((h, v));
        }
        self.save_identity(&ident, &created_by, "unknown")?;
        Ok(learned)
    }

    /// Checks whether an identity's session works, logging in again if it
    /// doesn't and a recipe exists.
    pub async fn identity_check(&self, actor: &Actor, name: &str) -> Result<IdentityCheck> {
        let ident = self.load_identity(name)?;
        let Some(health) = ident.health.clone() else {
            return Ok(IdentityCheck {
                name: name.into(),
                status: "unknown".into(),
                notes: vec!["no health check configured".into()],
                exchange_id: None,
            });
        };
        let out = self.outgoing(parse_url_endpoint(&health.url)?, health.request.as_bytes(), true)?;
        if Tier::for_http_method(&out.method) != Tier::ActiveSafe {
            return Err(ServiceError::Invalid("health checks must use GET, HEAD or OPTIONS".into()));
        }
        match self.gate_send(actor, "identity_check", &out, Some(name), true, None)? {
            Authorization::Allowed { .. } => {}
            other => return Err(ServiceError::Invalid(format!("health check not allowed: {other:?}"))),
        }
        let mut notes = Vec::new();
        let mut sent = self.send_now(actor, &out, Some(&ident), true, "health").await?;
        let mut ok = sent.response.as_deref().is_some_and(|r| health.passes(r));
        if !ok && ident.login.is_some() {
            notes.push("health check failed; logging in again".into());
            match self.identity_login(name).await {
                Ok(l) => {
                    notes.push(format!("login ok ({})", l.join(", ")));
                    let fresh = self.load_identity(name)?;
                    sent = self.send_now(actor, &out, Some(&fresh), true, "health").await?;
                    ok = sent.response.as_deref().is_some_and(|r| health.passes(r));
                }
                Err(e) => notes.push(format!("login failed: {e}")),
            }
        }
        let status = if ok { "ok" } else { "logged_out" };
        let row = self.store.read(|db| db.get_identity(name))?;
        if let Some(mut row) = row {
            row.status = status.into();
            row.updated_ms = now_ms();
            self.store.write(|db| db.upsert_identity(&row))?;
        }
        Ok(IdentityCheck { name: name.into(), status: status.into(), notes, exchange_id: Some(sent.exchange_id) })
    }
}
