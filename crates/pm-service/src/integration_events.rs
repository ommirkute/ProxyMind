//! Notifications to Slack and webhooks (roadmap 3.5), driven by the event bus (ADR-0018): no polling.
//!
//! [`Service::run_integration_notifier`] subscribes once (`proxymind ui` and the desktop app start it next to the
//! workflow triggers) and turns four kinds of events into messages for the integrations a person enabled in this
//! installation and subscribed to them:
//!
//! - `finding_proven`: a proof run proved a finding (once per finding until its status moves away from `proven`);
//! - `finding_status_changed`: a finding's status changed to anything but `proven` (which has its own event);
//! - `scan_finished`: a scan task ended (done, failed, cancelled);
//! - `ci_summary`: the findings' counts when a scan task ends.
//!
//! The payloads carry fields of the finding with secrets redacted, never request or response text. Each
//! integration has its own rate limit (excess notifications are skipped and logged), a send is retried with a
//! doubling wait for transport errors, 429 and 5xx (bounded), and the outcome is in the delivery log either way.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pm_policy::{Actor, ActorKind};
use serde_json::Value;

use crate::events::{Delivery, Event};
use crate::integration_payload::{
    Brief, WebhookCount, WebhookData, WebhookFinding, WebhookIssue, WebhookLink, WebhookProof, WebhookScan,
    WebhookSummary, WebhookTop,
};
use crate::integrations::{Integration, IntegrationEvent, IntegrationKind};
use crate::{Result, Service};

/// Notifications being delivered at once; more wait for a slot.
const MAX_CONCURRENT: usize = 8;

impl Service {
    /// The enabled, trusted Slack and webhook integrations subscribed to `event`.
    fn subscribers(&self, event: IntegrationEvent) -> Vec<Integration> {
        self.integrations_load()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| matches!(i.kind, IntegrationKind::Slack | IntegrationKind::Webhook))
            .filter(|i| i.events.contains(&event) && self.integration_active(i))
            .collect()
    }

    fn all_secret_values(&self) -> Vec<String> {
        self.integrations_load().unwrap_or_default().iter().flat_map(|i| self.integration_secret_values(i)).collect()
    }

    /// A finding as the webhook payload and Slack message describe it.
    pub(crate) fn webhook_finding(&self, id: i64) -> Result<(WebhookFinding, Brief)> {
        let brief = self.finding_brief(id, &self.all_secret_values(), false)?;
        let links = self.issue_links_of(&self.finding_get(id)?);
        let f = WebhookFinding {
            id,
            title: brief.title.clone(),
            severity: brief.severity.clone(),
            status: brief.status.clone(),
            vuln_class: brief.vuln_class.clone(),
            url: brief.url.clone(),
            description: brief.description.clone(),
            issue: brief.issue.as_ref().map(|i| WebhookIssue {
                id: i.id.clone(),
                name: i.name.clone(),
                cwe: i.cwe.clone(),
                owasp: i.owasp.clone(),
            }),
            proof: brief.proof.as_ref().map(|p| WebhookProof {
                oracle: p.oracle.clone(),
                confidence: p.confidence.clone(),
                reasons: p.reasons.clone(),
            }),
            exchange_ids: brief.exchange_ids.clone(),
            issue_links: links
                .into_iter()
                .map(|l| WebhookLink { integration: l.integration, key: l.key, url: l.url })
                .collect(),
        };
        Ok((f, brief))
    }

    /// Sends a finding event to every subscribed integration.
    async fn notify_finding(&self, event: IntegrationEvent, id: i64, previous: Option<String>) {
        let subs = self.subscribers(event);
        if subs.is_empty() {
            return;
        }
        let Ok((finding, brief)) = self.webhook_finding(id) else { return };
        let what = match event {
            IntegrationEvent::FindingProven => "Finding proven".to_string(),
            _ => format!("Finding status: {}", brief.status),
        };
        let headline = format!(
            "ProxyMind: {what}: [{}] {} (#{id})",
            crate::integration_payload::severity_label(&brief.severity),
            brief.title
        );
        let data = WebhookData { finding: Some(finding), previous_status: previous, ..Default::default() };
        for i in subs {
            self.notify_one(&i, event.as_str(), Some(id), &headline, &data).await;
        }
    }

    /// The counts of the project's findings (false positives left out) and the most severe open ones.
    pub(crate) fn ci_summary(&self) -> Result<WebhookSummary> {
        const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
        let findings: Vec<Value> =
            self.finding_list(None)?.into_iter().filter(|f| f["status"] != "false_positive").collect();
        let rank = |s: &str| SEVERITIES.iter().position(|x| *x == s).unwrap_or(9);
        let by_severity = SEVERITIES
            .iter()
            .map(|s| WebhookCount {
                name: s.to_string(),
                count: findings.iter().filter(|f| f["severity"] == *s).count(),
            })
            .collect();
        let mut statuses: Vec<String> =
            findings.iter().filter_map(|f| f["status"].as_str().map(String::from)).collect();
        statuses.sort();
        statuses.dedup();
        let by_status = statuses
            .into_iter()
            .map(|s| WebhookCount { count: findings.iter().filter(|f| f["status"] == s.as_str()).count(), name: s })
            .collect();
        let mut open: Vec<&Value> =
            findings.iter().filter(|f| !matches!(f["status"].as_str(), Some("fixed" | "accepted_risk"))).collect();
        open.sort_by_key(|f| rank(f["severity"].as_str().unwrap_or("")));
        let secrets = self.all_secret_values();
        let top = open
            .into_iter()
            .take(10)
            .map(|f| WebhookTop {
                id: f["id"].as_i64().unwrap_or(0),
                title: self.scrub(f["title"].as_str().unwrap_or(""), &secrets),
                severity: f["severity"].as_str().unwrap_or("").to_string(),
                status: f["status"].as_str().unwrap_or("").to_string(),
            })
            .collect();
        Ok(WebhookSummary {
            findings: findings.len(),
            proven: findings.iter().filter(|f| f["status"] == "proven").count(),
            by_severity,
            by_status,
            top,
        })
    }

    /// Sends `scan_finished` and `ci_summary` for a scan task that ended.
    async fn notify_scan(&self, task: &str, state: &str) {
        let finished = self.subscribers(IntegrationEvent::ScanFinished);
        let summary = self.subscribers(IntegrationEvent::CiSummary);
        if finished.is_empty() && summary.is_empty() {
            return;
        }
        let me = Actor { kind: ActorKind::Human, name: "integrations".into() };
        if !finished.is_empty()
            && let Ok(v) = self.scan_task_status(&me, task)
        {
            let secrets = self.all_secret_values();
            let scrub = |s: &str| self.scrub(s, &secrets);
            let scan = WebhookScan {
                task_id: v.task_id.clone(),
                url: scrub(&v.url),
                state: state.to_string(),
                pages_crawled: v.pages_crawled,
                targets_done: v.targets_done,
                targets_total: v.targets_total,
                requests: v.requests,
                issues: v.issues.len(),
                error: v.error.as_deref().map(scrub),
            };
            let headline = format!("ProxyMind: scan {state}: {} ({} issues)", scan.url, scan.issues);
            let data = WebhookData { scan: Some(scan), ..Default::default() };
            for i in finished {
                self.notify_one(&i, IntegrationEvent::ScanFinished.as_str(), None, &headline, &data).await;
            }
        }
        if !summary.is_empty()
            && let Ok(s) = self.ci_summary()
        {
            let headline = format!("ProxyMind: scan summary: {} findings, {} proven", s.findings, s.proven);
            let data = WebhookData { summary: Some(s), ..Default::default() };
            for i in summary {
                self.notify_one(&i, IntegrationEvent::CiSummary.as_str(), None, &headline, &data).await;
            }
        }
    }

    fn finding_statuses(&self) -> HashMap<i64, String> {
        self.finding_list(None)
            .unwrap_or_default()
            .iter()
            .filter_map(|f| Some((f["id"].as_i64()?, f["status"].as_str()?.to_string())))
            .collect()
    }

    /// Delivers notifications for as long as the service lives: start it once next to the proxy. Events dropped while
    /// it lags are not replayed (a notification is best effort), but the statuses it compares against are re-read.
    pub async fn run_integration_notifier(self: Arc<Self>) {
        let mut sub = self.subscribe();
        let mut statuses = self.finding_statuses();
        let mut proven_sent: HashSet<i64> =
            statuses.iter().filter(|(_, s)| s.as_str() == "proven").map(|(id, _)| *id).collect();
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
        loop {
            let Some(delivery) = sub.recv().await else { return };
            let p = match delivery {
                Delivery::Event(p) => p,
                Delivery::Resync { .. } => {
                    statuses = self.finding_statuses();
                    continue;
                }
            };
            // What to send, decided here (so the order of events is kept); the sending happens in a task.
            let job: Option<(IntegrationEvent, i64, Option<String>)> = match &p.event {
                Event::ProofCompleted { verdict, finding_id: Some(id), .. } if verdict == "proven" => {
                    proven_sent.insert(*id).then_some((IntegrationEvent::FindingProven, *id, None))
                }
                Event::FindingChanged { id, status } => {
                    // The status at the time of the event (not whatever the row says by now), so a quick succession
                    // of changes is seen in order.
                    let before = statuses.insert(*id, status.clone());
                    if before.as_deref() == Some("proven") && status != "proven" {
                        proven_sent.remove(id);
                    }
                    match before {
                        Some(b) if b != *status && status != "proven" => {
                            Some((IntegrationEvent::FindingStatusChanged, *id, Some(b)))
                        }
                        _ => None,
                    }
                }
                Event::ScanStateChanged { task, state }
                    if matches!(state.as_str(), "done" | "failed" | "cancelled") =>
                {
                    let (svc, task, state) = (self.clone(), task.clone(), state.clone());
                    let Ok(permit) = slots.clone().acquire_owned().await else { return };
                    tokio::spawn(async move {
                        svc.notify_scan(&task, &state).await;
                        drop(permit);
                    });
                    None
                }
                _ => None,
            };
            if let Some((event, id, previous)) = job {
                let svc = self.clone();
                let Ok(permit) = slots.clone().acquire_owned().await else { return };
                tokio::spawn(async move {
                    svc.notify_finding(event, id, previous).await;
                    drop(permit);
                });
            }
        }
    }
}
