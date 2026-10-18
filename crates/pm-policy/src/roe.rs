//! Rules-of-engagement file (`roe.yaml`). Mirrors `schemas/roe.schema.json`.

use std::path::Path;

use ipnet::IpNet;
use serde::Deserialize;

use crate::scope::UrlPattern;
use crate::window::TimeWindow;
use crate::{ActorKind, Decision, PolicyError, Tier};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoe {
    version: u32,
    #[serde(default)]
    engagement: Engagement,
    scope: RawScope,
    #[serde(default)]
    windows: Option<RawWindows>,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    tiers: RawTiers,
    #[serde(default)]
    data: DataRules,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engagement {
    pub name: Option<String>,
    pub client: Option<String>,
    pub reference: Option<String>,
    /// First day testing is allowed (inclusive), in the windows' time zone.
    pub starts: Option<jiff::civil::Date>,
    /// Last day testing is allowed (inclusive).
    pub ends: Option<jiff::civil::Date>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScope {
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    deny_networks: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindows {
    timezone: String,
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_rps")]
    pub max_rps_per_host: f64,
    #[serde(default = "default_concurrency")]
    pub max_concurrency: u32,
}

fn default_rps() -> f64 {
    10.0
}
fn default_concurrency() -> u32 {
    5
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_rps_per_host: default_rps(), max_concurrency: default_concurrency() }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTiers {
    human: Option<TierPolicy>,
    agent: Option<TierPolicy>,
    plugin: Option<TierPolicy>,
}

/// What an actor kind may do in each tier. Missing entries use the defaults
/// from RFC 0001.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierPolicy {
    pub read: Option<Decision>,
    pub passive: Option<Decision>,
    pub active_safe: Option<Decision>,
    pub active_intrusive: Option<Decision>,
    pub destructive: Option<Decision>,
}

impl TierPolicy {
    fn get(&self, tier: Tier) -> Option<Decision> {
        match tier {
            Tier::Read => self.read,
            Tier::Passive => self.passive,
            Tier::ActiveSafe => self.active_safe,
            Tier::ActiveIntrusive => self.active_intrusive,
            Tier::Destructive => self.destructive,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRules {
    #[serde(default = "yes")]
    pub redact_before_llm: bool,
    #[serde(default)]
    pub allow_cloud_models: bool,
}

fn yes() -> bool {
    true
}

impl Default for DataRules {
    fn default() -> Self {
        Self { redact_before_llm: true, allow_cloud_models: false }
    }
}

/// A validated rules-of-engagement file.
#[derive(Debug, Clone)]
pub struct Roe {
    pub engagement: Engagement,
    pub include: Vec<UrlPattern>,
    pub exclude: Vec<UrlPattern>,
    pub deny_networks: Vec<IpNet>,
    pub timezone: jiff::tz::TimeZone,
    pub windows: Vec<TimeWindow>,
    pub limits: Limits,
    pub data: DataRules,
    tiers: RawTiers,
}

impl Roe {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::Roe(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(yaml: &str) -> Result<Self, PolicyError> {
        let raw: RawRoe = serde_saphyr::from_str(yaml).map_err(|e| PolicyError::Roe(e.to_string()))?;
        if raw.version != 1 {
            return Err(PolicyError::Roe(format!("unsupported ROE version {} (expected 1)", raw.version)));
        }
        if raw.scope.include.is_empty() {
            return Err(PolicyError::Roe("scope.include must list at least one URL".into()));
        }
        let include = raw.scope.include.iter().map(|p| UrlPattern::parse(p)).collect::<Result<_, _>>()?;
        let exclude = raw.scope.exclude.iter().map(|p| UrlPattern::parse(p)).collect::<Result<_, _>>()?;
        let deny_networks = raw
            .scope
            .deny_networks
            .iter()
            .map(|n| n.parse::<IpNet>().map_err(|_| PolicyError::Roe(format!("bad network in deny_networks: {n}"))))
            .collect::<Result<_, _>>()?;

        let (timezone, windows) = match &raw.windows {
            None => (jiff::tz::TimeZone::UTC, Vec::new()),
            Some(w) => {
                let tz = jiff::tz::TimeZone::get(&w.timezone)
                    .map_err(|e| PolicyError::Roe(format!("unknown time zone {:?}: {e}", w.timezone)))?;
                let windows = w.allowed.iter().map(|s| TimeWindow::parse(s)).collect::<Result<_, _>>()?;
                (tz, windows)
            }
        };

        if !(raw.limits.max_rps_per_host > 0.0 && raw.limits.max_rps_per_host.is_finite()) {
            return Err(PolicyError::Roe("limits.max_rps_per_host must be a positive number".into()));
        }
        if raw.limits.max_concurrency == 0 {
            return Err(PolicyError::Roe("limits.max_concurrency must be at least 1".into()));
        }
        if let (Some(s), Some(e)) = (raw.engagement.starts, raw.engagement.ends)
            && e < s
        {
            return Err(PolicyError::Roe("engagement.ends is before engagement.starts".into()));
        }

        Ok(Self {
            engagement: raw.engagement,
            include,
            exclude,
            deny_networks,
            timezone,
            windows,
            limits: raw.limits,
            data: raw.data,
            tiers: raw.tiers,
        })
    }

    /// The decision for an actor kind and tier, falling back to defaults.
    pub fn tier_decision(&self, actor: ActorKind, tier: Tier) -> Decision {
        let configured = match actor {
            ActorKind::Human => self.tiers.human,
            ActorKind::Agent => self.tiers.agent,
            ActorKind::Plugin | ActorKind::Scanner => self.tiers.plugin,
        };
        configured.and_then(|p| p.get(tier)).unwrap_or_else(|| default_decision(actor, tier))
    }
}

/// Defaults from RFC 0001. Unknown or automated actors get the strictest set.
pub fn default_decision(actor: ActorKind, tier: Tier) -> Decision {
    use Decision::*;
    match (actor, tier) {
        (_, Tier::Read | Tier::Passive) => Allow,
        (ActorKind::Human, Tier::Destructive) => Approve,
        (ActorKind::Human, _) => Allow,
        (ActorKind::Agent, Tier::ActiveSafe) => Allow,
        (ActorKind::Agent, Tier::ActiveIntrusive) => Approve,
        (ActorKind::Agent, Tier::Destructive) => Deny,
        (ActorKind::Plugin | ActorKind::Scanner, Tier::ActiveSafe) => Approve,
        (ActorKind::Plugin | ActorKind::Scanner, _) => Deny,
    }
}
