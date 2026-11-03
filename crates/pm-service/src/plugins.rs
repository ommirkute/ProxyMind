//! Plugins as the service sees them (ADR-0014, ADR-0015): the user's
//! registry, turning plugins on and off, and active checks.
//!
//! An active check asks the plugin for requests, gates them as one action
//! (the approval shows exactly the requests that will be sent and covers
//! nothing else), sends each through the normal send path (scope per
//! request, rate limits, identities, history) and hands the results back
//! to the plugin, whose issues come back as leads.

use std::path::PathBuf;

use pm_policy::{Actor, ActorKind, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Authorization, Result, Service, ServiceError};
use pm_replay::Endpoint;

const ACTION: &str = "plugin_check";

/// An installed plugin, for lists.
#[derive(Debug, Clone, Serialize)]
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
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginsView {
    pub plugins: Vec<PluginInfo>,
    /// What the sandbox does on this machine.
    pub sandbox: pm_plugin::sandbox::Status,
    /// Where the registry is (plugins are per user, never per project).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginCheckRequest {
    pub plugin: String,
    /// The recorded exchange to check.
    pub exchange_id: i64,
    /// Send the requests as this identity.
    pub identity: Option<String>,
    /// From an earlier `pending_approval`: sends the requests shown then.
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginCheckIssue {
    /// `<plugin>/<check>`.
    pub check: String,
    pub title: String,
    pub severity: String,
    pub evidence: String,
    pub exchange_id: i64,
}

#[derive(Debug, Clone, Serialize)]
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
        let _ = self.plugin_home.set(home);
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
        let plugins = self
            .installed_plugins()
            .into_iter()
            .map(|p| PluginInfo {
                kinds: p.manifest.kinds(),
                max_requests: p.manifest.active.as_ref().map(|a| a.limit()),
                name: p.manifest.name,
                version: p.manifest.version,
                description: p.manifest.description,
                enabled: p.enabled,
                dir: p.dir.display().to_string(),
            })
            .collect();
        PluginsView {
            plugins,
            sandbox: pm_plugin::sandbox::status(),
            registry: self.plugin_home.get().map(|h| h.join(pm_plugin::REGISTRY).display().to_string()),
        }
    }

    /// Turns a plugin on or off in the user's registry. Humans only.
    pub fn plugin_set_enabled(&self, actor: &Actor, name: &str, enabled: bool) -> Result<PluginsView> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people can turn plugins on or off (they run code)".into()));
        }
        let home =
            self.plugin_home.get().ok_or_else(|| ServiceError::Invalid("no plugin registry in this process".into()))?;
        let mut reg = pm_plugin::Registry::load(home).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        if !reg.set_enabled(name, enabled) {
            return Err(ServiceError::NotFound(format!("plugin {name}")));
        }
        reg.save().map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.audit(&actor.id(), "plugin_enable", json!({ "plugin": name, "enabled": enabled }), "allow")?;
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
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let ex = self
            .store
            .lock()
            .get_exchange(req.exchange_id)?
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
            let request = self.store.lock().get_exchange(sent.exchange_id)?.map(|e| e.request).unwrap_or_default();
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
