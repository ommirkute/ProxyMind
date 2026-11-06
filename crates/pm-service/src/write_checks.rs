//! Write checks: the API description's state-changing operations on one
//! user's objects, tried once as their owner (ReDoS on string fields) and
//! once as another user (broken object-level authorization on writes).
//! These change data and can slow the server, so one gate decision at the
//! destructive tier covers the whole step: it needs a person's approval
//! unless the rules of engagement allow destructive actions.

use std::time::Instant;

use pm_policy::{Actor, Tier};
use serde::Serialize;
use serde_json::{Value, json};

use crate::auto::ScanLead;
use crate::findings::NewFinding;
use crate::replay::{Outgoing, parse_url_endpoint};
use crate::{Authorization, Result, Service};

/// Most described write operations one run tries.
const MAX_OPERATIONS: usize = 10;
/// Lengths of the backtracking probe; the time should grow exponentially.
const REDOS_LENGTHS: [usize; 3] = [16, 22, 26];
/// The longest probe must take at least this long, and this many times the shortest.
const REDOS_MIN_MS: u64 = 1500;
const REDOS_FACTOR: u64 = 8;

#[derive(Debug, Clone, Default, Serialize)]
pub struct WriteSweep {
    /// Described write operations matched to a user's object.
    pub tried: usize,
    pub requests: usize,
    pub leads: Vec<ScanLead>,
    pub notes: Vec<String>,
    /// Set when approval is needed (the step sent nothing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_approval: Option<String>,
}

/// A described write operation aimed at one user's object.
struct Target {
    method: String,
    template: String,
    /// The example request with the owner's object in the path.
    raw: String,
    owner: String,
    object: String,
    attacker: Option<String>,
    /// A recorded read of the object (as its owner), to check a write took effect.
    read: Option<String>,
}

/// `raw`'s string fields made unique with `marker` (an email stays an email).
fn marked(raw: &str, marker: &str) -> Option<String> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut v: Value = serde_json::from_str(body).ok()?;
    for (_, x) in v.as_object_mut()?.iter_mut() {
        if let Value::String(s) = x {
            *s = match s.split_once('@') {
                Some((l, d)) => format!("{l}{marker}@{d}"),
                None => format!("{s}{marker}"),
            };
        }
    }
    Some(format!("{head}\r\n\r\n{v}"))
}

/// The JSON body's top-level string fields.
fn string_fields(raw: &str) -> Vec<String> {
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(o)) => o.into_iter().filter(|(_, v)| v.is_string()).map(|(k, _)| k).take(4).collect(),
        _ => Vec::new(),
    }
}

fn with_field(raw: &str, field: &str, value: &str) -> Option<String> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut v: Value = serde_json::from_str(body).ok()?;
    v.as_object_mut()?.insert(field.into(), Value::String(value.into()));
    Some(format!("{head}\r\n\r\n{v}"))
}

/// `template`'s first `{param}` replaced with `value`, other parameters
/// taken from the example's own path (same segment).
fn fill_path(template: &str, example_path: &str, value: &str) -> String {
    let ex: Vec<&str> = example_path.split('?').next().unwrap_or("").split('/').collect();
    let mut first = true;
    template
        .split('/')
        .enumerate()
        .map(|(i, seg)| {
            if seg.starts_with('{') && seg.ends_with('}') {
                if std::mem::take(&mut first) {
                    pm_tools_encode(value)
                } else {
                    ex.get(i).copied().unwrap_or("1").to_string()
                }
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn pm_tools_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Service {
    fn write_targets(&self) -> Result<(Vec<Target>, Option<String>, Vec<String>)> {
        let mut notes = Vec::new();
        let spec = self.openapi_get()?;
        let base = spec["base_url"].as_str().map(str::to_string);
        #[derive(serde::Deserialize)]
        struct Op {
            method: String,
            path: String,
            example_request: String,
        }
        let ops: Vec<Op> = serde_json::from_value(spec["operations"].clone()).unwrap_or_default();
        if ops.is_empty() {
            notes.push("no API description imported: write checks need one".into());
            return Ok((Vec::new(), base, notes));
        }
        let model = self.model()?;
        let ids = self.identity_list()?;
        let admin = |n: &str| ids.iter().any(|i| i.name == n && i.role.to_ascii_lowercase().contains("admin"));
        let users: Vec<&str> = ids.iter().map(|i| i.name.as_str()).filter(|n| !admin(n)).collect();
        let mut out = Vec::new();
        for op in ops
            .iter()
            .filter(|o| ["PUT", "PATCH", "DELETE", "POST"].contains(&o.method.as_str()) && o.path.contains('{'))
        {
            if out.len() >= MAX_OPERATIONS {
                break;
            }
            // The read operation whose template starts this one names the object type.
            let Some(read) = model.operations.iter().filter(|m| m.object_type.is_some()).find(|m| {
                let t = m.template.as_str();
                op.path.starts_with(t) && op.path.as_bytes().get(t.len()).is_none_or(|&b| b == b'/') && t.contains('{')
            }) else {
                continue;
            };
            let kind = read.object_type.clone().unwrap_or_default();
            let Some(obj) = model
                .objects
                .iter()
                .find(|o| o.object_type == kind && o.owner.as_deref().is_some_and(|w| users.contains(&w)))
            else {
                continue;
            };
            let owner = obj.owner.clone().unwrap_or_default();
            let attacker = users.iter().find(|u| **u != owner).map(|u| (*u).to_string());
            let Some((line, rest)) = op.example_request.split_once("\r\n") else { continue };
            let mut parts = line.splitn(3, ' ');
            let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            let path = fill_path(&op.path, target, &obj.id);
            // A recorded GET of the object, to read it back as its owner.
            let read = obj.seen_in.iter().rev().find_map(|&id| {
                let e = self.store.lock().get_exchange(id).ok().flatten()?;
                (e.summary.method == "GET"
                    && e.summary.path.split('?').next() == Some(&fill_path(&read.template, &e.summary.path, &obj.id)))
                .then(|| self.redactor.redact(&String::from_utf8_lossy(&e.request)))
            });
            out.push(Target {
                method: method.into(),
                template: op.path.clone(),
                raw: format!("{method} {path} {version}\r\n{rest}"),
                owner,
                object: format!("{kind} {}", obj.id),
                attacker,
                read,
            });
        }
        if out.is_empty() {
            notes.push("no described write operation matched an object a test identity owns".into());
        }
        Ok((out, base, notes))
    }

    /// Runs the write checks (see the module docs).
    pub async fn auto_write_checks(&self, actor: &Actor) -> Result<WriteSweep> {
        let (targets, base, notes) = self.write_targets()?;
        let mut sweep = WriteSweep { tried: targets.len(), notes, ..Default::default() };
        let Some(first) = targets.first() else { return Ok(sweep) };
        let Some(base) = base else {
            sweep.notes.push("the API description has no server URL".into());
            return Ok(sweep);
        };
        let endpoint = parse_url_endpoint(&base)?;
        let first_out = self.outgoing(endpoint.clone(), first.raw.as_bytes(), true)?;
        let extra = json!({
            "write_checks": targets.iter().map(|t| format!("{} {} ({})", t.method, t.template, t.object)).collect::<Vec<_>>(),
        });
        match self.gate_send_with(
            actor,
            "auto_write_checks",
            &first_out,
            None,
            true,
            None,
            Some(Tier::Destructive),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => {
                sweep.notes.push(format!("denied: {}", reasons.join("; ")));
                return Ok(sweep);
            }
            Authorization::PendingApproval { approval_id, summary, .. } => {
                sweep.pending_approval = Some(format!("{approval_id}: {summary}"));
                return Ok(sweep);
            }
        }
        // ReDoS first, as the owner on their own object (nothing else is changed by
        // a value the server rejects); then authorization, which may change data.
        for t in &targets {
            if let Some(lead) = self.redos_probe(actor, &endpoint, t, &mut sweep).await? {
                sweep.leads.push(lead);
            }
        }
        for t in &targets {
            if let Some(lead) = self.write_authz_probe(actor, &endpoint, t, &mut sweep).await? {
                sweep.leads.push(lead);
            }
        }
        Ok(sweep)
    }

    async fn timed(&self, actor: &Actor, out: &Outgoing, identity: &str) -> Result<(crate::replay::Sent, u64)> {
        let started = Instant::now();
        let (s, _) = self.send_as(actor, out, Some(identity), true, "scan").await?;
        Ok((s, started.elapsed().as_millis() as u64))
    }

    async fn redos_probe(
        &self,
        actor: &Actor,
        endpoint: &pm_replay::Endpoint,
        t: &Target,
        sweep: &mut WriteSweep,
    ) -> Result<Option<ScanLead>> {
        for field in string_fields(&t.raw) {
            let mut times = Vec::new();
            let mut last = None;
            for n in REDOS_LENGTHS {
                let value = format!("{}!", "a".repeat(n));
                let Some(raw) = with_field(&t.raw, &field, &value) else { break };
                let out = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
                let (sent, ms) = self.timed(actor, &out, &t.owner).await?;
                sweep.requests += 1;
                times.push(ms);
                last = Some(sent.exchange_id);
                // Still fast at the middle length: no exponential blow-up here.
                if n == REDOS_LENGTHS[1] && ms < 40 {
                    break;
                }
            }
            if times.len() == REDOS_LENGTHS.len()
                && times[2] >= REDOS_MIN_MS
                && times[2] >= REDOS_FACTOR * times[0].max(1)
            {
                // Confirm: the long probe is slow again (not a one-off stall).
                let raw = with_field(&t.raw, &field, &format!("{}!", "a".repeat(REDOS_LENGTHS[2]))).unwrap_or_default();
                let out = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
                let (_, again) = self.timed(actor, &out, &t.owner).await?;
                sweep.requests += 1;
                if again < REDOS_MIN_MS {
                    continue;
                }
                let evidence = format!(
                    "{} took {} / {} / {} ms for {} / {} / {} characters (then {again} ms again): the time grows \
                     exponentially with the input",
                    field, times[0], times[1], times[2], REDOS_LENGTHS[0], REDOS_LENGTHS[1], REDOS_LENGTHS[2]
                );
                return self
                    .write_lead(
                        actor,
                        t,
                        "redos",
                        "medium",
                        &format!("ReDoS in {} {} ({field})", t.method, t.template),
                        &evidence,
                        last,
                    )
                    .map(Some);
            }
        }
        Ok(None)
    }

    async fn write_authz_probe(
        &self,
        actor: &Actor,
        endpoint: &pm_replay::Endpoint,
        t: &Target,
        sweep: &mut WriteSweep,
    ) -> Result<Option<ScanLead>> {
        let Some(attacker) = &t.attacker else { return Ok(None) };
        // Unique values, so a read-back can tell whose object changed.
        let marker = format!("pm{}", &pm_oast::new_token()[..6]);
        let raw = marked(&t.raw, &marker).unwrap_or_else(|| t.raw.clone());
        let out = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
        // Anonymous first: a write anyone may make isn't an authorization bug between users.
        let (anon, _) = self.timed(actor, &out, pm_identity::ANONYMOUS).await?;
        sweep.requests += 1;
        if !anon.status.is_some_and(|s| s == 401 || s == 403) {
            return Ok(None);
        }
        let (as_other, _) = self.timed(actor, &out, attacker).await?;
        sweep.requests += 1;
        let Some(status) = as_other.status.filter(|s| (200..300).contains(s)) else { return Ok(None) };
        // Read the object back as its owner. A written field that shows there
        // without our value means the write went elsewhere (often the caller's
        // own account); fields reads never show (passwords) can't be checked.
        let mut verified = false;
        if let Some(read) = &t.read {
            let out = self.outgoing(endpoint.clone(), read.as_bytes(), true)?;
            let (back, _) = self.timed(actor, &out, &t.owner).await?;
            sweep.requests += 1;
            let body = back
                .response
                .as_deref()
                .map(|r| String::from_utf8_lossy(pm_http::split_message(r).1).into_owned())
                .unwrap_or_default();
            let shown = string_fields(&t.raw).iter().any(|f| body.contains(&format!("\"{f}\"")));
            if shown && !body.contains(&marker) {
                return Ok(None);
            }
            verified = shown;
        }
        sweep
            .notes
            .push(format!("{attacker} changed {}'s {} (the test account may need resetting)", t.owner, t.object));
        let evidence = format!(
            "{attacker} sent {} {} on {}'s {} and got {status}; without credentials it was refused ({}){}",
            t.method,
            t.template,
            t.owner,
            t.object,
            anon.status.unwrap_or_default(),
            if verified {
                "; reading the object back as its owner shows the new value"
            } else {
                "; the change can't be read back"
            }
        );
        self.write_lead(
            actor,
            t,
            "bola",
            "high",
            &format!("{attacker} can change {}'s {} ({} {})", t.owner, t.object, t.method, t.template),
            &evidence,
            Some(as_other.exchange_id),
        )
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_lead(
        &self,
        actor: &Actor,
        t: &Target,
        class: &str,
        severity: &str,
        title: &str,
        evidence: &str,
        exchange: Option<i64>,
    ) -> Result<ScanLead> {
        let finding = self.finding_create(
            actor,
            NewFinding {
                title: title.into(),
                vuln_class: class.into(),
                severity: severity.into(),
                description: format!("{evidence}. Found by the automatic write checks; not proven yet."),
                url: None,
                evidence: exchange.into_iter().collect(),
                hypothesis_id: None,
            },
        )?;
        Ok(ScanLead {
            operation: format!("{} {}", t.method, t.template),
            check: class.into(),
            finding_id: finding["id"].as_i64().unwrap_or_default(),
            evidence: evidence.chars().take(200).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_fields() {
        assert_eq!(
            fill_path("/users/v1/{username}/password", "/users/v1/name1/password", "bob x"),
            "/users/v1/bob%20x/password"
        );
        assert_eq!(fill_path("/a/{x}/b/{y}", "/a/1/b/7", "me"), "/a/me/b/7");
        let raw = "PUT /u HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"email\":\"a@b\",\"n\":1}";
        assert_eq!(string_fields(raw), ["email"]);
        assert!(
            with_field(raw, "email", "aaa!").unwrap().ends_with("{\"email\":\"aaa!\",\"n\":1}")
                || with_field(raw, "email", "aaa!").unwrap().contains("\"email\":\"aaa!\"")
        );
    }
}
