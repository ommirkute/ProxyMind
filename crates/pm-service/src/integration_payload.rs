//! What integrations send (roadmap 3.5): the texts and JSON bodies for Jira, GitHub, GitLab, Slack and webhooks.
//!
//! Pure: no I/O, no secrets. Everything in a [`Brief`] has already been through the redactor (`pm-service` builds it
//! in `integrations.rs`), and the builders here only arrange it. Finding text comes from target traffic, so it is
//! treated as untrusted: Markdown mentions and GitLab quick actions are defanged, evidence goes in code blocks that
//! cannot be closed from inside, Jira text goes in `{noformat}`, and Slack text is escaped.

use ring::hmac;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Version of the webhook payload (`"v"`). A field is only ever added; a change that is not additive gets a new number.
pub const WEBHOOK_VERSION: u32 = 1;

/// A finding as an integration sends it. Every string is redacted.
#[derive(Debug, Clone, Default)]
pub(crate) struct Brief {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub vuln_class: String,
    pub url: String,
    pub description: String,
    pub issue: Option<IssueBrief>,
    pub proof: Option<ProofBrief>,
    pub steps: Vec<Step>,
    pub exchange_ids: Vec<i64>,
    pub remediation: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct IssueBrief {
    pub id: String,
    pub name: String,
    pub cwe: Vec<String>,
    pub owasp: String,
    pub owasp_api: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ProofBrief {
    pub oracle: String,
    pub confidence: String,
    pub reasons: Vec<String>,
}

/// One request of the reproduction: the exchange it came from and its redacted text.
#[derive(Debug, Clone, Default)]
pub(crate) struct Step {
    pub exchange_id: i64,
    pub identity: Option<String>,
    pub request: String,
}

/// `critical` → `Critical`.
pub(crate) fn severity_label(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// The issue's title, cut to what GitHub (256) and GitLab (255) accept.
pub(crate) fn title(b: &Brief) -> String {
    let t: String = format!("[{}] {}", severity_label(&b.severity), one_line(&b.title)).chars().take(240).collect();
    t.trim().to_string()
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Text that cannot mention people or run GitLab quick actions when a tracker renders it as Markdown.
pub(crate) fn defang_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for line in s.lines() {
        // A quick action is a line that starts with `/` (GitLab); a heading or list marker is harmless.
        let trimmed = line.trim_start();
        if trimmed.starts_with('/') {
            out.push('\u{200b}');
        }
        for c in line.chars() {
            out.push(c);
            if c == '@' {
                out.push('\u{200b}');
            }
        }
        out.push('\n');
    }
    out.trim_end().to_string()
}

/// A fenced code block whose fence is longer than any run of backticks inside, so the text cannot close it.
pub(crate) fn fence(lang: &str, text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let f = "`".repeat((longest + 1).max(3));
    format!("{f}{lang}\n{text}\n{f}")
}

fn inline_code(s: &str) -> String {
    format!("`{}`", one_line(s).replace('`', "'"))
}

fn class_line(b: &Brief) -> String {
    match &b.issue {
        Some(i) => {
            let mut parts = vec![i.name.clone()];
            if !i.cwe.is_empty() {
                parts.push(i.cwe.join(", "));
            }
            if !i.owasp.is_empty() {
                parts.push(format!("OWASP {}", i.owasp));
            }
            if let Some(a) = &i.owasp_api {
                parts.push(format!("OWASP API {a}"));
            }
            parts.join(" · ")
        }
        None => b.vuln_class.clone(),
    }
}

/// The body of a GitHub or GitLab issue (Markdown).
pub(crate) fn markdown_body(b: &Brief, version: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!("**Severity:** {}  \n", severity_label(&b.severity)));
    s.push_str(&format!("**Status:** {}  \n", one_line(&b.status)));
    s.push_str(&format!("**ProxyMind finding:** #{}  \n", b.id));
    s.push_str(&format!("**Class:** {}  \n", one_line(&class_line(b))));
    s.push_str(&format!("**URL:** {}\n\n", inline_code(&b.url)));
    s.push_str("### Description\n\n");
    s.push_str(&defang_markdown(&b.description));
    s.push_str("\n\n");
    if let Some(p) = &b.proof {
        s.push_str("### Proof\n\n");
        s.push_str(&format!(
            "Verified by ProxyMind's `{}` check (confidence: {}).\n",
            one_line(&p.oracle),
            one_line(&p.confidence)
        ));
        for r in &p.reasons {
            s.push_str(&format!("- {}\n", defang_markdown(&one_line(r))));
        }
        s.push('\n');
    }
    if !b.steps.is_empty() {
        s.push_str("### Reproduction\n\nThe requests below are recorded exchanges; credentials are replaced by placeholders.\n\n");
        for st in &b.steps {
            let who = st.identity.as_deref().map(|i| format!(" as {}", inline_code(i))).unwrap_or_default();
            s.push_str(&format!("Exchange #{}{who}\n\n{}\n\n", st.exchange_id, fence("http", &st.request)));
        }
    }
    if !b.remediation.is_empty() {
        s.push_str("### Remediation\n\n");
        s.push_str(&defang_markdown(&b.remediation));
        s.push_str("\n\n");
    }
    s.push_str("---\n");
    let ids = b.exchange_ids.iter().map(|i| format!("#{i}")).collect::<Vec<_>>().join(", ");
    s.push_str(&format!(
        "Created by ProxyMind {version}. Evidence exchanges: {}.\n",
        if ids.is_empty() { "none".into() } else { ids }
    ));
    // GitHub refuses bodies over 65 536 characters; GitLab over 1 048 576.
    cut(&s, 60_000)
}

/// The description of a Jira issue (wiki markup, REST API v2).
pub(crate) fn jira_body(b: &Brief, version: &str) -> String {
    let noformat = |t: &str| format!("{{noformat}}\n{}\n{{noformat}}", t.replace("{noformat}", "{ noformat }"));
    let mut s = String::new();
    s.push_str(&format!("*Severity:* {}\n", severity_label(&b.severity)));
    s.push_str(&format!("*Status:* {}\n", one_line(&b.status)));
    s.push_str(&format!("*ProxyMind finding:* #{}\n", b.id));
    s.push_str(&format!("*Class:* {}\n", one_line(&class_line(b)).replace(['{', '[', ']'], "")));
    s.push_str(&format!("*URL:* {}\n\n", noformat(&one_line(&b.url))));
    s.push_str("h3. Description\n");
    s.push_str(&noformat(&b.description));
    s.push_str("\n\n");
    if let Some(p) = &b.proof {
        s.push_str("h3. Proof\n");
        let mut t = format!("check: {} (confidence: {})", one_line(&p.oracle), one_line(&p.confidence));
        for r in &p.reasons {
            t.push_str(&format!("\n- {}", one_line(r)));
        }
        s.push_str(&noformat(&t));
        s.push_str("\n\n");
    }
    if !b.steps.is_empty() {
        s.push_str("h3. Reproduction\nRecorded requests; credentials are replaced by placeholders.\n");
        for st in &b.steps {
            let who = st
                .identity
                .as_deref()
                .map(|i| format!(" as {}", one_line(i).replace(['{', '['], "")))
                .unwrap_or_default();
            s.push_str(&format!("Exchange #{}{who}\n{}\n", st.exchange_id, noformat(&st.request)));
        }
        s.push('\n');
    }
    if !b.remediation.is_empty() {
        s.push_str("h3. Remediation\n");
        s.push_str(&noformat(&b.remediation));
        s.push_str("\n\n");
    }
    let ids = b.exchange_ids.iter().map(|i| format!("#{i}")).collect::<Vec<_>>().join(", ");
    s.push_str(&format!(
        "_Created by ProxyMind {version}. Evidence exchanges: {}._\n",
        if ids.is_empty() { "none".into() } else { ids }
    ));
    // Jira Cloud allows 32 767 characters in a description.
    cut(&s, 30_000)
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push_str("\n… (cut)");
    t
}

/// Jira labels cannot hold spaces.
pub(crate) fn jira_label(s: &str) -> String {
    s.chars().map(|c| if c.is_whitespace() { '-' } else { c }).collect()
}

/// Escapes text for Slack's `mrkdwn` (`&`, `<`, `>`), which also stops `<!channel>` and link tricks.
pub(crate) fn slack_escape(s: &str) -> String {
    one_line(s).replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A Slack message: `text` (the notification and fallback) and one section block of `lines` (already escaped).
pub(crate) fn slack_message(headline: &str, lines: &[String]) -> Value {
    let body = lines.join("\n");
    let mut blocks =
        vec![json!({"type": "section", "text": {"type": "mrkdwn", "text": cut(&format!("*{headline}*"), 3000)}})];
    if !body.is_empty() {
        blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": cut(&body, 2900)}}));
    }
    json!({ "text": cut(headline, 2900), "blocks": blocks })
}

/// `sha256=<hex>` over `body`, the value of `X-ProxyMind-Signature`.
pub(crate) fn signature(secret: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256={hex}")
}

// ---- webhook payload v1 --------------------------------------------------------------------------------------

/// The JSON a webhook receives (`Content-Type: application/json`). Versioned: `v` is `1`; fields may be added, never
/// renamed or removed within a version. Every string is redacted like a report shown to a model.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookPayload {
    /// Payload version, `1`.
    pub v: u32,
    /// Unique id of this delivery (also sent as `X-ProxyMind-Delivery`); a receiver can drop one it has seen.
    pub id: String,
    /// When the event happened, RFC 3339 UTC (also signed as part of the body, so a replayed request is visible).
    pub ts: String,
    /// `finding_proven`, `finding_status_changed`, `scan_finished`, `ci_summary` or `test`.
    pub event: String,
    /// The engagement's name from the rules of engagement, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engagement: Option<String>,
    /// What the event is about; the key depends on `event`.
    pub data: WebhookData,
}

/// The `data` of a webhook payload: exactly one of the fields is present, matching `event`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct WebhookData {
    /// `finding_proven` and `finding_status_changed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<WebhookFinding>,
    /// `finding_status_changed`: the status before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_status: Option<String>,
    /// `scan_finished`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<WebhookScan>,
    /// `ci_summary`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<WebhookSummary>,
    /// `test`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A finding in a webhook payload (no request or response text: fetch evidence from ProxyMind by id).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookFinding {
    /// The finding's id in the project.
    pub id: i64,
    pub title: String,
    /// critical, high, medium, low or info.
    pub severity: String,
    /// suspected, proven, confirmed, false_positive, reported, fixed or accepted_risk.
    pub status: String,
    /// The finding's class (idor, sqli, ...).
    pub vuln_class: String,
    pub url: String,
    pub description: String,
    /// From the issue library, when the class is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<WebhookIssue>,
    /// The proof that verified it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<WebhookProof>,
    /// Exchanges that show the issue.
    pub exchange_ids: Vec<i64>,
    /// Issues already created for it in trackers (`key`, `url`).
    pub issue_links: Vec<WebhookLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookIssue {
    pub id: String,
    pub name: String,
    /// `CWE-639`, ...
    pub cwe: Vec<String>,
    pub owasp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookProof {
    pub oracle: String,
    pub confidence: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookLink {
    /// Name of the integration that created it.
    pub integration: String,
    /// `PROJ-12`, `#34` or `!`-less GitLab iid.
    pub key: String,
    pub url: String,
}

/// A finished scan task.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookScan {
    pub task_id: String,
    /// The start URL.
    pub url: String,
    /// done, failed or cancelled.
    pub state: String,
    pub pages_crawled: usize,
    pub targets_done: usize,
    pub targets_total: usize,
    pub requests: usize,
    /// Issues the task recorded.
    pub issues: usize,
    /// Why it failed, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The state of the project's findings when a scan ended.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookSummary {
    /// Findings that are not false positives.
    pub findings: usize,
    pub proven: usize,
    /// Counts per severity, most severe first (every severity listed).
    pub by_severity: Vec<WebhookCount>,
    /// Counts per status.
    pub by_status: Vec<WebhookCount>,
    /// The most severe open findings (at most 10).
    pub top: Vec<WebhookTop>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookCount {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebhookTop {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brief() -> Brief {
        Brief {
            id: 7,
            title: "IDOR in /api/orders".into(),
            severity: "high".into(),
            status: "proven".into(),
            vuln_class: "idor".into(),
            url: "https://app.test/api/orders/1".into(),
            description: "Other users' orders are readable.\n/close\nping @everyone ```break```".into(),
            issue: Some(IssueBrief {
                id: "idor".into(),
                name: "Insecure direct object reference".into(),
                cwe: vec!["CWE-639".into()],
                owasp: "A01:2021 Broken Access Control".into(),
                owasp_api: None,
            }),
            proof: Some(ProofBrief {
                oracle: "differential_authz".into(),
                confidence: "high".into(),
                reasons: vec!["same body".into()],
            }),
            steps: vec![Step {
                exchange_id: 3,
                identity: Some("bob".into()),
                request: "GET /api/orders/1 HTTP/1.1\nCookie: session={{secret:cookie_session_1}}\n```\n".into(),
            }],
            exchange_ids: vec![3, 4],
            remediation: "Check ownership.".into(),
        }
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        assert_eq!(
            signature(b"Jefe", b"what do ya want for nothing?"),
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn markdown_body_has_the_fields_and_cannot_be_hijacked() {
        let md = markdown_body(&brief(), "0.2.0");
        for want in ["**Severity:** High", "#7", "CWE-639", "A01:2021", "differential_authz", "Exchange #3", "#3, #4"] {
            assert!(md.contains(want), "{want} in\n{md}");
        }
        assert!(!md.contains("\n/close"), "quick action defanged:\n{md}");
        assert!(!md.contains("@everyone"), "mention defanged");
        // The request contains a ``` line: the fence around it must be longer.
        assert!(md.contains("````http"), "{md}");
        assert!(title(&brief()).starts_with("[High] IDOR"));
    }

    #[test]
    fn jira_body_uses_noformat_and_survives_markup_in_text() {
        let mut b = brief();
        b.description = "{noformat} {panel} [~admin]".into();
        let j = jira_body(&b, "0.2.0");
        assert!(j.contains("h3. Description\n{noformat}\n{ noformat } {panel} [~admin]\n{noformat}"), "{j}");
        assert!(j.contains("*Severity:* High"));
    }

    #[test]
    fn slack_text_is_escaped() {
        assert_eq!(slack_escape("<!channel> a&b"), "&lt;!channel&gt; a&amp;b");
        let m = slack_message("Proven", &["x".into()]);
        assert_eq!(m["text"], "Proven");
        assert_eq!(m["blocks"].as_array().unwrap().len(), 2);
    }
}
