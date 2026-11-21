//! Plugins as the service sees them (ADR-0014, ADR-0015): the user's
//! registry, turning plugins on and off, and active checks.
//!
//! An active check asks the plugin for requests, gates them as one action
//! (the approval shows exactly the requests that will be sent and covers
//! nothing else), sends each through the normal send path (scope per
//! request, rate limits, identities, history) and hands the results back
//! to the plugin, whose issues come back as leads.

use std::path::PathBuf;

use std::sync::Arc;

use pm_plugin::hooks::{Failure, HookEngine};
use pm_plugin::v2::{self, HookKind, HookMatch, OnError};
use pm_policy::{Actor, Target, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::access::{Denial, Perm};
use crate::api_types::HookAction;
use crate::{Authorization, Event, Result, Service, ServiceError};
use pm_replay::Endpoint;

const ACTION: &str = "plugin_check";

/// An installed plugin, for lists.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    /// "passive" and/or "active".
    pub kinds: Vec<&'static str>,
    pub enabled: bool,
    pub dir: String,
    /// Most requests one active check may send.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<usize>,
    /// Panels the plugin adds: (id, title).
    pub panels: Vec<(String, String)>,
    /// Who signed it, as checked at install.
    pub signature: pm_plugin::sign::Signature,
    /// Plugin API version: 1 (no permissions) or 2.
    pub api: u32,
    /// The permissions a v2 plugin declares.
    pub permissions: Vec<String>,
    /// The permissions a person accepted. A v2 plugin only gets what it declares and a person accepted.
    pub accepted_permissions: Vec<String>,
    /// The declared permissions differ from the accepted ones: the plugin stays off until a person accepts them.
    pub needs_review: bool,
    /// Traffic hooks the plugin declares.
    pub hooks: Vec<HookInfo>,
}

/// A traffic hook of a plugin, as set up and as running.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct HookInfo {
    pub kind: HookKind,
    /// A person turned it on.
    pub enabled: bool,
    /// `off`, `on`, `paused` or `unavailable` (turned on, but not runnable: see `blocked_reason`).
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_reason: Option<String>,
    pub on_error: OnError,
    pub timeout_ms: u64,
    pub matcher: HookMatch,
    /// Place among the hooks of its kind, first to run = 1.
    pub order: usize,
    /// Messages sent to it and changed by it since the proxy started it (this process).
    pub calls: u64,
    pub changed: u64,
    /// Latest failures, newest last.
    pub failures: Vec<Failure>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PluginsView {
    pub plugins: Vec<PluginInfo>,
    /// What the sandbox does on this machine.
    pub sandbox: pm_plugin::sandbox::Status,
    /// Where the registry is (plugins are per user, never per project).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
// `default` makes every field optional to serde; the schema still lists what a call needs.
#[schemars(extend("required" = ["plugin", "exchange_id"]))]
pub struct PluginCheckRequest {
    /// Name of the plugin to run.
    pub plugin: String,
    /// The recorded exchange to check.
    pub exchange_id: i64,
    /// Send the requests as this identity.
    pub identity: Option<String>,
    /// From an earlier `pending_approval`: sends the requests shown then.
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PluginCheckIssue {
    /// `<plugin>/<check>`.
    pub check: String,
    pub title: String,
    pub severity: String,
    pub evidence: String,
    pub exchange_id: i64,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PluginCheckResult {
    Done {
        issues: Vec<PluginCheckIssue>,
        /// The exchanges the plugin's requests were recorded as.
        exchange_ids: Vec<i64>,
        notes: Vec<String>,
    },
    PendingApproval {
        approval_id: String,
        summary: String,
        reasons: Vec<String>,
        /// The requests the approval covers.
        requests: Vec<pm_plugin::active::Probe>,
    },
    Denied {
        reasons: Vec<String>,
    },
}

impl Service {
    /// Plugins come from the user's registry in `home`, read each time they
    /// are used (so `proxymind plugin add` takes effect without a restart).
    pub fn attach_plugin_home(&self, home: PathBuf) {
        let _ = self.plugin_home.set(home.clone());
        // The same folder holds this installation's record of which projects it trusts.
        self.trust_attach_home(home);
    }

    fn installed_plugins(&self) -> Vec<pm_plugin::Installed> {
        match self.plugin_home.get() {
            Some(home) => match pm_plugin::Registry::load(home) {
                Ok(r) => r.plugins,
                Err(e) => {
                    tracing::warn!("plugins not loaded: {e}");
                    Vec::new()
                }
            },
            None => self.plugins.read().clone(),
        }
    }

    /// The enabled plugins (for the passive scan).
    pub(crate) fn enabled_plugins(&self) -> Vec<pm_plugin::Installed> {
        self.installed_plugins().into_iter().filter(|p| p.enabled).collect()
    }

    pub fn plugin_list(&self) -> PluginsView {
        // `proxymind plugin add` in another process may have changed the registry: bring the hooks in line (this
        // is also what keeps a plugin whose permissions changed from running until a person accepts them).
        self.sync_hooks();
        let reg = self.registry();
        let engine = self.hook_engine.get();
        let plugins = self
            .installed_plugins()
            .into_iter()
            .map(|p| {
                let name = p.manifest.name.clone();
                let (accepted, needs_review) = match &reg {
                    Some(r) if p.manifest.is_v2() => (r.accepted(&name), r.needs_review(&name)),
                    _ => (if p.manifest.is_v2() { p.manifest.declared_permissions() } else { vec![] }, false),
                };
                let hooks = HookKind::ALL
                    .into_iter()
                    .filter_map(|kind| {
                        let spec = p.manifest.hook(kind)?;
                        let enabled = reg.as_ref().is_some_and(|r| r.hook_on(&name, kind));
                        let blocked_reason = reg.as_ref().and_then(|r| r.hook_blocker(&name, kind));
                        let status = engine.and_then(|e| e.status(&name, kind));
                        let paused = status.as_ref().is_some_and(|s| s.paused);
                        let state = match (enabled, &blocked_reason, paused) {
                            (false, _, _) => "off",
                            (true, Some(_), _) => "unavailable",
                            (true, None, true) => "paused",
                            (true, None, false) => "on",
                        };
                        let order = reg
                            .as_ref()
                            .and_then(|r| r.hooks_in_order().iter().filter(|h| h.1 == kind).position(|h| h.0 == name))
                            .map_or(1, |i| i + 1);
                        Some(HookInfo {
                            kind,
                            enabled,
                            state: state.into(),
                            blocked_reason,
                            paused_reason: status.as_ref().and_then(|s| s.paused_reason.clone()),
                            on_error: spec.on_error,
                            timeout_ms: spec.timeout_ms(),
                            matcher: spec.matcher.clone(),
                            order,
                            calls: status.as_ref().map_or(0, |s| s.calls),
                            changed: status.as_ref().map_or(0, |s| s.changed),
                            failures: status.map(|s| s.failures).unwrap_or_default(),
                        })
                    })
                    .collect();
                PluginInfo {
                    kinds: p.manifest.kinds(),
                    max_requests: p.manifest.active.as_ref().map(|a| a.limit()),
                    api: p.manifest.api_version(),
                    permissions: p.manifest.declared_permissions(),
                    accepted_permissions: accepted,
                    needs_review,
                    hooks,
                    name: p.manifest.name,
                    version: p.manifest.version,
                    description: p.manifest.description,
                    enabled: p.enabled,
                    dir: p.dir.display().to_string(),
                    panels: p.manifest.panels.iter().map(|x| (x.id.clone(), x.title.clone())).collect(),
                    signature: p.signature,
                }
            })
            .collect();
        PluginsView {
            plugins,
            sandbox: pm_plugin::sandbox::status(),
            registry: self.plugin_home.get().map(|h| h.join(pm_plugin::REGISTRY).display().to_string()),
        }
    }

    fn registry(&self) -> Option<pm_plugin::Registry> {
        pm_plugin::Registry::load(self.plugin_home.get()?).ok()
    }

    /// What a plugin may do now. None for version 1 plugins, which have no permissions to check. A v2 plugin gets
    /// what its manifest declares and a person accepted (plugins handed over with `set_plugins`, which have no
    /// registry, get what they declare).
    fn permissions_of(&self, p: &pm_plugin::Installed) -> Option<Vec<String>> {
        if !p.manifest.is_v2() {
            return None;
        }
        match self.registry() {
            Some(r) => r.effective_permissions(&p.manifest.name),
            None => Some(p.manifest.declared_permissions()),
        }
    }

    /// Refuses a feature a v2 plugin did not declare, or declared but nobody accepted.
    fn require_plugin_permission(&self, p: &pm_plugin::Installed, perm: &str) -> Result<()> {
        let Some(granted) = self.permissions_of(p) else { return Ok(()) };
        if granted.iter().any(|g| g == perm) {
            return Ok(());
        }
        let name = &p.manifest.name;
        Err(ServiceError::Invalid(if p.manifest.declared_permissions().iter().any(|d| d == perm) {
            format!("plugin {name} declares the {perm} permission but nobody accepted it yet")
        } else {
            format!(
                "plugin {name} did not declare the {perm} permission (api 2 plugins may only use what they declare)"
            )
        }))
    }

    /// The enabled plugins that may run passive checks.
    pub(crate) fn passive_plugins(&self) -> Vec<pm_plugin::Installed> {
        self.enabled_plugins()
            .into_iter()
            .filter(|p| self.permissions_of(p).is_none_or(|g| g.iter().any(|x| x == v2::CHECKS_PASSIVE)))
            .collect()
    }

    /// Connects the proxy's hook engine (ADR-0020): hooks only see in-scope traffic by this project's rules of
    /// engagement, a hook that pauses itself reaches the event bus, and the hooks a person turned on start now.
    pub fn attach_hooks(&self, engine: Arc<HookEngine>) {
        let policy = self.policy.clone();
        engine.set_scope(Arc::new(move |scheme, host, port, path| {
            Target::from_parts(scheme, host, port, path).is_ok_and(|t| policy.scope_check(&t).is_ok())
        }));
        let bus = self.bus.clone();
        engine.set_observer(Arc::new(move |plugin, what| {
            bus.publish(Event::PluginsChanged { plugin: plugin.to_string(), what: what.to_string() }, None);
        }));
        let _ = self.hook_engine.set(engine);
        self.sync_hooks();
    }

    pub fn hook_engine(&self) -> Option<&Arc<HookEngine>> {
        self.hook_engine.get()
    }

    /// Gives the engine the hooks the registry says should run.
    fn sync_hooks(&self) {
        let (Some(engine), Some(reg)) = (self.hook_engine.get(), self.registry()) else { return };
        engine.configure(reg.active_hooks());
    }

    fn plugin_changed(&self, plugin: &str, what: &str) {
        self.sync_hooks();
        self.bus.publish(Event::PluginsChanged { plugin: plugin.to_string(), what: what.to_string() }, None);
    }

    /// The refusal for a non-person: audited, and it names the action (`action`), as the checks did before ADR-0022.
    fn plugin_denial(action: &'static str, detail: serde_json::Value) -> Denial {
        Denial::message(format!(
            "only people can do this ({action}): plugins run code and hooks change traffic, so an agent can't turn them on, accept their permissions or set them up"
        ))
        .and_audit(action, detail)
    }

    fn registry_for_change(&self) -> Result<pm_plugin::Registry> {
        let home =
            self.plugin_home.get().ok_or_else(|| ServiceError::Invalid("no plugin registry in this process".into()))?;
        pm_plugin::Registry::load(home).map_err(|e| ServiceError::Invalid(e.to_string()))
    }

    /// A person accepts the permissions a v2 plugin declares (the first time, or after an update changed them),
    /// which also turns the plugin on. Audited.
    pub fn plugin_accept_permissions(&self, actor: &Actor, name: &str) -> Result<PluginsView> {
        self.require_actor_with(
            actor,
            Perm::PluginsManage,
            Self::plugin_denial("plugin_accept_permissions", json!({ "plugin": name })),
        )?;
        let mut reg = self.registry_for_change()?;
        let perms = reg.accept_permissions(name).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        reg.save().map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.audit(&actor.id(), "plugin_accept_permissions", json!({ "plugin": name, "permissions": perms }), "allow")?;
        self.plugin_changed(name, "permissions_accepted");
        Ok(self.plugin_list())
    }

    /// Turns a hook on or off, moves it, or pauses or resumes it. People only; audited.
    pub fn plugin_hook_set(
        &self,
        actor: &Actor,
        name: &str,
        kind: HookKind,
        action: HookAction,
    ) -> Result<PluginsView> {
        let detail = json!({ "plugin": name, "hook": kind.as_str(), "action": action });
        self.require_actor_with(actor, Perm::HooksManage, Self::plugin_denial("plugin_hook", detail.clone()))?;
        let mut reg = self.registry_for_change()?;
        let plugin = reg.find(name).ok_or_else(|| ServiceError::NotFound(format!("plugin {name}")))?;
        if plugin.manifest.hook(kind).is_none() {
            return Err(ServiceError::NotFound(format!("{} hook of plugin {name}", kind.as_str())));
        }
        let what = match action {
            HookAction::Enable => {
                if let Some(why) = reg.hook_blocker(name, kind) {
                    return Err(ServiceError::Invalid(format!("can't turn on {name}'s {} hook: {why}", kind.as_str())));
                }
                reg.set_hook_on(name, kind, true);
                "hook_enabled"
            }
            HookAction::Disable => {
                reg.set_hook_on(name, kind, false);
                "hook_disabled"
            }
            HookAction::Up | HookAction::Down => {
                let delta = if action == HookAction::Up { -1 } else { 1 };
                reg.move_hook(name, kind, delta).map_err(|e| ServiceError::Invalid(e.to_string()))?;
                "hook_order"
            }
            HookAction::Pause | HookAction::Resume => {
                let engine = self.hook_engine.get().ok_or_else(|| {
                    ServiceError::Invalid("hooks run in the proxy process (proxymind ui): none here".into())
                })?;
                let done =
                    if action == HookAction::Pause { engine.pause(name, kind) } else { engine.resume(name, kind) };
                if !done {
                    return Err(ServiceError::Invalid(format!(
                        "the {} hook of {name} isn't running: turn it on first",
                        kind.as_str()
                    )));
                }
                if action == HookAction::Pause { "hook_paused" } else { "hook_resumed" }
            }
        };
        if !matches!(action, HookAction::Pause | HookAction::Resume) {
            reg.save().map_err(|e| ServiceError::Invalid(e.to_string()))?;
        }
        self.audit(&actor.id(), "plugin_hook", detail, "allow")?;
        self.plugin_changed(name, what);
        Ok(self.plugin_list())
    }

    /// Runs a plugin's panel over the newest recorded exchanges (default
    /// 500, max 5000). The plugin runs sandboxed and sends nothing; for
    /// agents the output is redacted and marked untrusted.
    pub fn plugin_panel(
        &self,
        actor: &Actor,
        plugin: &str,
        panel: &str,
        limit: Option<usize>,
    ) -> Result<pm_plugin::panel::PanelData> {
        let p = self
            .enabled_plugins()
            .into_iter()
            .find(|p| p.manifest.name == plugin)
            .ok_or_else(|| ServiceError::NotFound(format!("enabled plugin {plugin}")))?;
        self.require_plugin_permission(&p, v2::PANELS)?;
        // A v2 panel only gets recorded exchanges if the plugin declared (and a person accepted) history.read.
        let rows = if self.require_plugin_permission(&p, v2::HISTORY_READ).is_err() {
            Vec::new()
        } else {
            self.store.read(|db| {
                db.search_exchanges(&pm_store::HistoryFilter {
                    limit: Some(limit.unwrap_or(500).clamp(1, 5000)),
                    ..Default::default()
                })
            })?
        };
        let mut lines = Vec::with_capacity(rows.len());
        for s in rows {
            let Some(ex) = self.store.read(|db| db.get_exchange(s.id))? else { continue };
            lines.push(pm_plugin::ExchangeLine {
                exchange_id: s.id,
                scheme: s.scheme.clone(),
                host: s.host.clone(),
                port: s.port,
                method: s.method.clone(),
                path: s.path.clone(),
                status: s.status,
                request: pm_core::base64(&ex.request),
                response: ex.response.as_deref().map(pm_core::base64),
            });
        }
        let mut data =
            pm_plugin::panel::run_panel(&p, panel, &lines).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        if let Some(r) = self.redactor_for(actor) {
            data.text = pm_ai::wrap_untrusted(&r.redact(&data.text));
            for row in &mut data.rows {
                for c in row.iter_mut() {
                    *c = r.redact(c);
                }
            }
        }
        Ok(data)
    }

    /// Turns a plugin on or off in the user's registry. Humans only. A v2 plugin whose permissions nobody
    /// accepted can't be turned on.
    pub fn plugin_set_enabled(&self, actor: &Actor, name: &str, enabled: bool) -> Result<PluginsView> {
        self.require_actor_with(
            actor,
            Perm::PluginsManage,
            Self::plugin_denial("plugin_enable", json!({ "plugin": name, "enabled": enabled })),
        )?;
        let mut reg = self.registry_for_change()?;
        reg.set_enabled_checked(name, enabled).map_err(|e| match e {
            pm_plugin::PluginError::Invalid(m) if m.starts_with("no plugin") => {
                ServiceError::NotFound(format!("plugin {name}"))
            }
            e => ServiceError::Invalid(e.to_string()),
        })?;
        reg.save().map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.audit(&actor.id(), "plugin_enable", json!({ "plugin": name, "enabled": enabled }), "allow")?;
        self.plugin_changed(name, if enabled { "enabled" } else { "disabled" });
        Ok(self.plugin_list())
    }

    /// Runs an active-check plugin on one recorded exchange.
    pub async fn plugin_check(&self, actor: &Actor, req: PluginCheckRequest) -> Result<PluginCheckResult> {
        let plugin = self
            .enabled_plugins()
            .into_iter()
            .find(|p| p.manifest.name == req.plugin)
            .ok_or_else(|| ServiceError::NotFound(format!("enabled plugin {}", req.plugin)))?;
        if plugin.manifest.active.is_none() {
            return Err(ServiceError::Invalid(format!("{} has no active check", req.plugin)));
        }
        self.require_plugin_permission(&plugin, v2::CHECKS_ACTIVE)?;
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let ex = self
            .store
            .read(|db| db.get_exchange(req.exchange_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        let s = &ex.summary;
        let endpoint = Endpoint::new(&s.scheme, &s.host, s.port);
        let line = pm_plugin::ExchangeLine {
            exchange_id: s.id,
            scheme: s.scheme.clone(),
            host: s.host.clone(),
            port: s.port,
            method: s.method.clone(),
            path: s.path.clone(),
            status: s.status,
            request: pm_core::base64(&ex.request),
            response: ex.response.as_deref().map(pm_core::base64),
        };
        let mut notes = Vec::new();

        // The requests: the ones an approval was given for, or new ones.
        let probes: Vec<pm_plugin::active::Probe> = match &req.approval_id {
            Some(id) => {
                let row = self.approval(id)?.ok_or_else(|| ServiceError::NotFound(format!("approval {id}")))?;
                let params: serde_json::Value = serde_json::from_str(&row.params).unwrap_or_default();
                let p = &params["extra"]["plugin_check"];
                if p["plugin"] != json!(req.plugin) || p["exchange_id"] != json!(req.exchange_id) {
                    return Err(ServiceError::Approval(format!("approval {id} is for another plugin check")));
                }
                serde_json::from_value(p["requests"].clone()).unwrap_or_default()
            }
            None => {
                let p = plugin.clone();
                let l = line.clone();
                let (probes, rejected) = tokio::task::spawn_blocking(move || pm_plugin::active::probes(&p, &l))
                    .await
                    .map_err(|e| ServiceError::Invalid(e.to_string()))?
                    .map_err(|e| ServiceError::Invalid(e.to_string()))?;
                if rejected > 0 {
                    notes.push(format!("{rejected} line(s) from the plugin were not valid requests and were dropped"));
                }
                probes
            }
        };
        if probes.is_empty() {
            return Ok(PluginCheckResult::Done { issues: vec![], exchange_ids: vec![], notes });
        }

        // One gate decision for the whole batch, at least intrusive: these are
        // payloads chosen by code outside ProxyMind.
        let mut outs = Vec::with_capacity(probes.len());
        let mut tier = Tier::ActiveIntrusive;
        for p in &probes {
            let out = self.outgoing(endpoint.clone(), p.raw.as_bytes(), true)?;
            tier = tier.max(Tier::for_http_request(&out.raw).0);
            outs.push(out);
        }
        let baseline = self.outgoing(endpoint.clone(), &ex.request, false)?;
        let extra = json!({ "plugin_check": {
            "plugin": req.plugin, "version": plugin.manifest.version, "exchange_id": req.exchange_id,
            "requests": probes,
        }});
        match self.gate_send_with(
            actor,
            ACTION,
            &baseline,
            req.identity.as_deref(),
            true,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(PluginCheckResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(PluginCheckResult::PendingApproval {
                    approval_id,
                    summary: format!("plugin {} ({} requests): {summary}", req.plugin, probes.len()),
                    reasons,
                    requests: probes,
                });
            }
        }

        // Send, then let the plugin judge.
        let mut results = Vec::with_capacity(outs.len());
        for (i, (p, out)) in probes.iter().zip(&outs).enumerate() {
            let (sent, mut n) = self.send_as(actor, out, req.identity.as_deref(), true, "plugin").await?;
            notes.append(&mut n);
            let request =
                self.store.read(|db| db.get_exchange(sent.exchange_id))?.map(|e| e.request).unwrap_or_default();
            results.push(pm_plugin::active::ProbeResult {
                index: i,
                note: p.note.clone(),
                exchange_id: sent.exchange_id,
                status: sent.status,
                elapsed_ms: sent.elapsed_ms,
                request: pm_core::base64(&request),
                response: sent.response.as_deref().map(pm_core::base64),
                error: sent.error.clone(),
            });
        }
        let exchange_ids: Vec<i64> = results.iter().map(|r| r.exchange_id).collect();
        let p = plugin.clone();
        let judged = tokio::task::spawn_blocking(move || pm_plugin::active::judge(&p, &line, &results))
            .await
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let issues = match judged {
            Ok((found, rejected)) => {
                if rejected > 0 {
                    notes.push(format!("{rejected} issue line(s) from the plugin were rejected"));
                }
                found
                    .into_iter()
                    .map(|i| PluginCheckIssue {
                        check: format!("{}/{}", i.plugin, i.check),
                        title: i.title,
                        severity: i.severity,
                        evidence: i.evidence,
                        exchange_id: i.exchange_id,
                    })
                    .collect()
            }
            Err(e) => {
                notes.push(format!("the plugin failed while judging: {e}"));
                vec![]
            }
        };
        self.audit(
            &actor.id(),
            "plugin_check_done",
            json!({ "plugin": req.plugin, "exchange_id": req.exchange_id, "sent": exchange_ids.len(),
                    "issues": issues.len() }),
            "allow",
        )?;
        Ok(PluginCheckResult::Done { issues, exchange_ids, notes })
    }
}
