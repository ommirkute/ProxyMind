//! Passive scanning: run the checks in `pm-scan` over recorded traffic and
//! group duplicates. Sends nothing, so it is a read action.

use std::collections::BTreeMap;

use pm_policy::{Actor, ActorKind};
use pm_scan::Severity;
use pm_store::HistoryFilter;
use serde::{Deserialize, Serialize};

use crate::{Result, Service};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanFilter {
    /// Only exchanges whose host contains this.
    pub host: Option<String>,
    /// How many recent exchanges to look at (default 2000, max 20000).
    pub limit: Option<usize>,
    /// Only issues at least this severe: info, low, medium or high.
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanIssue {
    /// A built-in check id, or `<plugin>/<check>` for a plugin's.
    pub check: String,
    pub title: String,
    pub severity: Severity,
    /// scheme://host[:port]
    pub origin: String,
    /// Path template, or "*" for host-wide issues such as missing headers.
    pub path: String,
    /// What was seen (from the target: untrusted; wrapped for agents).
    pub evidence: String,
    pub count: usize,
    /// First few exchanges showing it.
    pub exchange_ids: Vec<i64>,
}

fn severity(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        _ => return None,
    })
}

impl Service {
    /// Passive issues in recorded traffic, most severe first. These are
    /// leads to test, not findings.
    pub fn scan_passive(&self, actor: &Actor, filter: &ScanFilter) -> Result<Vec<ScanIssue>> {
        let min = match filter.min_severity.as_deref() {
            Some(s) => severity(s)
                .ok_or_else(|| crate::ServiceError::Invalid("min_severity: info, low, medium or high".into()))?,
            None => Severity::Info,
        };
        let limit = filter.limit.unwrap_or(2000).clamp(1, 20_000);
        let summaries = self.store.lock().search_exchanges(&HistoryFilter {
            host: filter.host.clone(),
            limit: Some(limit),
            ..Default::default()
        })?;
        let mut groups: BTreeMap<(String, String, String, String), ScanIssue> = BTreeMap::new();
        let mut lines: Vec<pm_plugin::ExchangeLine> = Vec::new();
        let mut where_of: std::collections::HashMap<i64, (String, String)> = std::collections::HashMap::new();
        let plugins = self.plugins.read().clone();
        for s in summaries {
            let Some(ex) = self.store.lock().get_exchange(s.id)? else { continue };
            let Some(resp) = ex.response.as_deref() else { continue };
            let converted;
            let resp = if pm_http::h2text::is_http2_response(resp) {
                match pm_http::h2text::to_http1_response(resp) {
                    Some(r) => {
                        converted = r;
                        &converted[..]
                    }
                    None => continue,
                }
            } else {
                resp
            };
            let (head, body) = pm_http::split_message(resp);
            let Ok(head) = pm_http::parse_response_head(head) else { continue };
            let decoded = pm_ai::body::decode(&head.headers, body);
            let issues = pm_scan::check(&pm_scan::Exchange {
                scheme: &s.scheme,
                request: &ex.request,
                status: head.status,
                headers: &head.headers,
                body: &decoded.bytes,
            });
            let origin = pm_core::authority(&s.scheme, &s.host, s.port);
            let origin = format!("{}://{origin}", s.scheme);
            if !plugins.is_empty() {
                where_of.insert(s.id, (origin.clone(), pm_model::template_path(&s.path).0));
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
            for i in issues.into_iter().filter(|i| i.severity >= min) {
                let path = if i.host_wide { "*".to_string() } else { pm_model::template_path(&s.path).0 };
                let key_evidence = if i.host_wide { String::new() } else { i.evidence.clone() };
                let g = groups.entry((i.check.to_string(), origin.clone(), path.clone(), key_evidence)).or_insert_with(
                    || ScanIssue {
                        check: i.check.to_string(),
                        title: i.title.to_string(),
                        severity: i.severity,
                        origin: origin.clone(),
                        path,
                        evidence: i.evidence.clone(),
                        count: 0,
                        exchange_ids: Vec::new(),
                    },
                );
                g.count += 1;
                if g.exchange_ids.len() < 5 {
                    g.exchange_ids.push(s.id);
                }
            }
        }
        // Plugins see the same exchanges; their issues are grouped the same way.
        for p in &plugins {
            let name = p.manifest.name.clone();
            let found = match pm_plugin::run_passive(p, &lines) {
                Ok((found, _rejected)) => found,
                Err(e) => {
                    groups.insert(
                        (format!("{name}/plugin_error"), String::new(), String::new(), String::new()),
                        ScanIssue {
                            check: format!("{name}/plugin_error"),
                            title: format!("Plugin {name} failed"),
                            severity: Severity::Info,
                            origin: String::new(),
                            path: String::new(),
                            evidence: e.to_string(),
                            count: 1,
                            exchange_ids: vec![],
                        },
                    );
                    continue;
                }
            };
            for i in found {
                let Some(sev) = severity(&i.severity).filter(|s| *s >= min) else { continue };
                let Some((origin, path)) = where_of.get(&i.exchange_id).cloned() else { continue };
                let check = format!("{name}/{}", i.check);
                let g = groups.entry((check.clone(), origin.clone(), path.clone(), i.evidence.clone())).or_insert_with(
                    || ScanIssue {
                        check,
                        title: i.title.clone(),
                        severity: sev,
                        origin,
                        path,
                        evidence: i.evidence.clone(),
                        count: 0,
                        exchange_ids: Vec::new(),
                    },
                );
                g.count += 1;
                if g.exchange_ids.len() < 5 {
                    g.exchange_ids.push(i.exchange_id);
                }
            }
        }
        let mut out: Vec<ScanIssue> = groups.into_values().collect();
        out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.check.cmp(&b.check)).then(a.origin.cmp(&b.origin)));
        if let Some(r) = self.redactor_for(actor) {
            for i in &mut out {
                i.evidence = r.redact(&i.evidence);
            }
        }
        if actor.kind == ActorKind::Agent {
            for i in &mut out {
                i.evidence = pm_ai::wrap_untrusted(&i.evidence);
            }
        }
        Ok(out)
    }
}
