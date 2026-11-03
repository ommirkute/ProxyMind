//! Active-check plugins: the plugin proposes requests, ProxyMind sends them.
//!
//! A check on one recorded exchange runs the plugin twice, each time with
//! one JSON object on stdin:
//!
//! 1. `{"phase":"probe","exchange":{…}}`: the plugin writes one line per
//!    request it wants sent, `{"raw":"GET /x?debug=1 HTTP/1.1\r\n…","note":"…"}`.
//!    Requests go to the exchange's own host (the request line must be
//!    origin-form, `/path`), through the policy gate: tiers, approvals,
//!    scope for each request, rate limits.
//! 2. `{"phase":"judge","exchange":{…},"results":[{…}]}`: each result has the
//!    probe's index and note, the exchange id it was recorded as, status,
//!    elapsed time and raw request/response (base64). The plugin writes
//!    issues in the passive format, about the original exchange or a probe.
//!
//! What a plugin writes is untrusted: probes are parsed and limited, issues
//! validated like passive ones.

use serde::{Deserialize, Serialize};

use crate::{ExchangeLine, Installed, PluginError, PluginIssue, Result, parse_issues, run, run_err};

/// Most requests one check may propose.
pub const MAX_PROBES: usize = 200;
/// Largest proposed request.
pub const MAX_PROBE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Active {
    /// Program and arguments, as for passive plugins.
    pub command: Vec<String>,
    /// Seconds per phase before the plugin is stopped (default 60, max 600).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Most requests per check (default 20, max 200).
    #[serde(default)]
    pub max_requests: Option<usize>,
}

impl Active {
    pub fn limit(&self) -> usize {
        self.max_requests.unwrap_or(20).clamp(1, MAX_PROBES)
    }
}

/// A request a plugin wants sent, after checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    /// HTTP/1.1 request text (CRLF or LF line ends).
    pub raw: String,
    /// What the probe tests, shown to the person approving it.
    #[serde(default)]
    pub note: String,
}

/// What happened to one probe, handed back to the plugin.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub index: usize,
    pub note: String,
    /// The exchange the request was recorded as (0 if it wasn't sent).
    pub exchange_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub elapsed_ms: u64,
    /// Raw bytes as sent, base64.
    pub request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn spec(p: &Installed) -> Result<&Active> {
    p.manifest.active.as_ref().ok_or_else(|| run_err(p, "not an active plugin".into()))
}

/// Parses phase-1 output. Returns the probes kept and how many lines were
/// rejected (not JSON, not a request, absolute-form, too big, over the limit).
pub fn parse_probes(output: &str, limit: usize) -> (Vec<Probe>, usize) {
    let mut probes = Vec::new();
    let mut rejected = 0;
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let ok = serde_json::from_str::<Probe>(line).ok().filter(|p| {
            if p.raw.len() > MAX_PROBE_BYTES {
                return false;
            }
            let text = p.raw.replace("\r\n", "\n").replace('\n', "\r\n");
            let head = match pm_http::find_head_end(text.as_bytes()) {
                Ok(Some(end)) => text.as_bytes()[..end].to_vec(),
                _ => format!("{}\r\n\r\n", text.trim_end()).into_bytes(),
            };
            // Origin-form only: the request goes to the exchange's own host.
            pm_http::parse_request_head(&head).is_ok_and(|h| h.target.starts_with('/'))
        });
        match ok {
            Some(mut p) if probes.len() < limit => {
                p.note = p.note.chars().filter(|c| !c.is_control()).take(200).collect();
                probes.push(p);
            }
            _ => rejected += 1,
        }
    }
    (probes, rejected)
}

/// Phase 1: the requests the plugin wants sent for `exchange`.
pub fn probes(p: &Installed, exchange: &ExchangeLine) -> Result<(Vec<Probe>, usize)> {
    let a = spec(p)?;
    let input = serde_json::to_vec(&serde_json::json!({ "phase": "probe", "exchange": exchange }))
        .map_err(|e| PluginError::Invalid(e.to_string()))?;
    let out = run(p, &a.command, a.timeout_seconds.unwrap_or(60), [input, b"\n".to_vec()].concat())?;
    Ok(parse_probes(&String::from_utf8_lossy(&out), a.limit()))
}

/// Phase 2: the plugin's issues, given what its requests got back. Issues
/// may name the original exchange or any probe's exchange.
pub fn judge(p: &Installed, exchange: &ExchangeLine, results: &[ProbeResult]) -> Result<(Vec<PluginIssue>, usize)> {
    let a = spec(p)?;
    let input = serde_json::to_vec(&serde_json::json!({ "phase": "judge", "exchange": exchange, "results": results }))
        .map_err(|e| PluginError::Invalid(e.to_string()))?;
    let out = run(p, &a.command, a.timeout_seconds.unwrap_or(60), [input, b"\n".to_vec()].concat())?;
    let mut known: std::collections::HashSet<i64> =
        results.iter().map(|r| r.exchange_id).filter(|id| *id > 0).collect();
    known.insert(exchange.exchange_id);
    Ok(parse_issues(&p.manifest.name, &String::from_utf8_lossy(&out), &known))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_checked() {
        let out = concat!(
            "{\"raw\":\"GET /a?debug=1 HTTP/1.1\\nHost: x\\n\\n\",\"note\":\"debug\\u0007 flag\"}\n",
            "{\"raw\":\"GET http://elsewhere.test/ HTTP/1.1\\r\\n\\r\\n\"}\n",
            "{\"raw\":\"CONNECT elsewhere.test:443 HTTP/1.1\\r\\n\\r\\n\"}\n",
            "{\"raw\":\"not http\"}\n",
            "{\"raw\":\"POST /b HTTP/1.1\"}\n",
            "{\"raw\":\"GET /c HTTP/1.1\\r\\n\\r\\n\"}\n",
            "nonsense\n"
        );
        let (probes, rejected) = parse_probes(out, 2);
        assert_eq!(
            probes.iter().map(|p| p.raw.lines().next().unwrap()).collect::<Vec<_>>(),
            ["GET /a?debug=1 HTTP/1.1", "POST /b HTTP/1.1"]
        );
        assert_eq!(probes[0].note, "debug flag");
        assert_eq!(rejected, 5, "absolute-form, CONNECT, not HTTP, over the limit, not JSON");
    }
}
