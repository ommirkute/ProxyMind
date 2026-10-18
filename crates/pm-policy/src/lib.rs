//! The policy gate: scope, rules of engagement, action tiers, approvals,
//! rate limits and the audit chain.
//!
//! Every action from every actor (human, agent, plugin) is checked here
//! before it runs (ADR-0005). The gate is deliberately strict: anything it
//! cannot positively place in scope is refused.

pub mod audit;
pub mod ratelimit;
pub mod roe;
pub mod scope;
pub mod window;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use ratelimit::{Permit, RateLimiter, Wait};
pub use roe::Roe;
pub use scope::{Target, UrlPattern};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("rules of engagement: {0}")]
    Roe(String),
    #[error("bad target: {0}")]
    Target(String),
    #[error("bad actor id {0:?} (expected kind:name, e.g. agent:claude-1)")]
    Actor(String),
    #[error("audit log is broken at record {seq}: {why}")]
    AuditBroken { seq: i64, why: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Approve,
    Deny,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Approve => "approve",
            Decision::Deny => "deny",
        }
    }
}

/// How risky an action is. See RFC 0001.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Read,
    Passive,
    ActiveSafe,
    ActiveIntrusive,
    Destructive,
}

impl Tier {
    /// Whether the action sends traffic to a target.
    pub fn is_active(self) -> bool {
        self >= Tier::ActiveSafe
    }

    /// Default tier for sending one HTTP request with this method.
    /// Payload-aware classification comes with the fuzzer and scanner.
    pub fn for_http_method(method: &str) -> Tier {
        match method.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Tier::ActiveSafe,
            "DELETE" => Tier::Destructive,
            _ => Tier::ActiveIntrusive,
        }
    }

    pub fn parse(s: &str) -> Option<Tier> {
        Some(match s {
            "read" => Tier::Read,
            "passive" => Tier::Passive,
            "active_safe" => Tier::ActiveSafe,
            "active_intrusive" => Tier::ActiveIntrusive,
            "destructive" => Tier::Destructive,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Human,
    Agent,
    Plugin,
    Scanner,
}

/// Who is acting, e.g. `agent:claude-1`. Set by the client adapter from its
/// credentials, never from request content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Actor {
    pub kind: ActorKind,
    pub name: String,
}

impl Actor {
    pub fn parse(id: &str) -> Result<Self, PolicyError> {
        let (kind, name) = id.split_once(':').ok_or_else(|| PolicyError::Actor(id.into()))?;
        let kind = match kind {
            "human" => ActorKind::Human,
            "agent" => ActorKind::Agent,
            "plugin" => ActorKind::Plugin,
            "scanner" => ActorKind::Scanner,
            _ => return Err(PolicyError::Actor(id.into())),
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c)) {
            return Err(PolicyError::Actor(id.into()));
        }
        Ok(Self { kind, name: name.into() })
    }

    pub fn id(&self) -> String {
        let kind = match self.kind {
            ActorKind::Human => "human",
            ActorKind::Agent => "agent",
            ActorKind::Plugin => "plugin",
            ActorKind::Scanner => "scanner",
        };
        format!("{kind}:{}", self.name)
    }
}

/// An action someone wants to take.
#[derive(Debug, Clone, Serialize)]
pub struct ActionRequest {
    pub actor: Actor,
    /// Operation name, e.g. `replay_send`.
    pub action: String,
    pub tier: Tier,
    /// The target, for actions that send traffic.
    #[serde(skip)]
    pub target: Option<Target>,
    /// Human-readable description shown in approval prompts.
    pub summary: String,
}

/// The gate's answer, with reasons a human (or model) can read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub decision: Decision,
    pub reasons: Vec<String>,
}

impl Verdict {
    fn deny(reason: impl Into<String>) -> Self {
        Self { decision: Decision::Deny, reasons: vec![reason.into()] }
    }
}

/// Evaluates actions against a rules-of-engagement file.
pub struct Policy {
    roe: Roe,
}

impl Policy {
    pub fn new(roe: Roe) -> Self {
        Self { roe }
    }

    pub fn roe(&self) -> &Roe {
        &self.roe
    }

    /// Whether a target is in scope, with the reason.
    pub fn scope_check(&self, t: &Target) -> Result<(), String> {
        if let Some(ip) = t.ip
            && let Some(net) = self.denied_network(ip)
        {
            return Err(format!("{ip} is in a denied network ({net})"));
        }
        if let Some(p) = self.roe.exclude.iter().find(|p| p.matches_lenient(t)) {
            return Err(format!("excluded by scope rule {}", p.text));
        }
        if !self.roe.include.iter().any(|p| p.matches(t)) {
            return Err(format!("{}://{}:{}{} is not in scope", t.scheme, t.host, t.port, t.path));
        }
        Ok(())
    }

    /// Checks addresses a host name resolved to, right before connecting.
    /// Stops in-scope names that point at denied networks (DNS rebinding).
    pub fn check_resolved(&self, addrs: &[IpAddr]) -> Result<(), String> {
        for &ip in addrs {
            if let Some(net) = self.denied_network(ip) {
                return Err(format!("host resolves to {ip}, which is in a denied network ({net})"));
            }
        }
        Ok(())
    }

    /// IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are checked as IPv4,
    /// so they can't slip past an IPv4 rule.
    fn denied_network(&self, ip: IpAddr) -> Option<&ipnet::IpNet> {
        let canonical = ip.to_canonical();
        self.roe.deny_networks.iter().find(|n| n.contains(&ip) || n.contains(&canonical))
    }

    fn time_check(&self, now: jiff::Timestamp) -> Result<(), String> {
        let local = now.to_zoned(self.roe.timezone.clone());
        let date = local.date();
        if let Some(s) = self.roe.engagement.starts
            && date < s
        {
            return Err(format!("the engagement starts on {s}"));
        }
        if let Some(e) = self.roe.engagement.ends
            && date > e
        {
            return Err(format!("the engagement ended on {e}"));
        }
        if !self.roe.windows.is_empty() && !self.roe.windows.iter().any(|w| w.contains(local.datetime())) {
            return Err(format!("outside the allowed testing windows ({})", local.strftime("%a %H:%M %Z")));
        }
        Ok(())
    }

    /// Decides whether an action may run now.
    pub fn evaluate(&self, req: &ActionRequest, now: jiff::Timestamp) -> Verdict {
        if req.tier.is_active() {
            let Some(target) = &req.target else {
                return Verdict::deny("active actions must name a target");
            };
            if let Err(why) = self.scope_check(target) {
                return Verdict::deny(why);
            }
            if let Err(why) = self.time_check(now) {
                return Verdict::deny(why);
            }
        }
        let decision = self.roe.tier_decision(req.actor.kind, req.tier);
        let tier = serde_json::to_value(req.tier).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        let reason = match decision {
            Decision::Allow => format!("{} actions are allowed for this actor", tier),
            Decision::Approve => format!("{} actions need human approval for this actor", tier),
            Decision::Deny => format!("{} actions are not allowed for this actor", tier),
        };
        Verdict { decision, reasons: vec![reason] }
    }
}

/// Hash of the parameters with object keys sorted, so the same parameters
/// always hash the same whatever order a client sent them in.
pub fn params_hash(params: &serde_json::Value) -> String {
    fn canonical(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(o) => {
                let mut keys: Vec<&String> = o.keys().collect();
                keys.sort();
                let mut m = serde_json::Map::new();
                for k in keys {
                    m.insert(k.clone(), canonical(&o[k]));
                }
                serde_json::Value::Object(m)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    // Serialize sorted keys explicitly: Map may preserve insertion order.
    fn write(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(o) => {
                let mut keys: Vec<&String> = o.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                    out.push(':');
                    write(&o[*k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(x, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut s = String::new();
    write(&canonical(params), &mut s);
    blake3::hash(s.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn params_hash_ignores_key_order() {
        let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":[3,{"q":1,"p":2}]}}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"a":{"x":[3,{"p":2,"q":1}],"y":2},"b":1}"#).unwrap();
        assert_eq!(super::params_hash(&a), super::params_hash(&b));
        let c: serde_json::Value = serde_json::from_str(r#"{"a":{"x":[{"p":2,"q":1},3],"y":2},"b":1}"#).unwrap();
        assert_ne!(super::params_hash(&a), super::params_hash(&c), "array order matters");
    }
}
