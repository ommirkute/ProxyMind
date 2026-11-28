//! A credential's tier cap (ADR-0022 step 5): the gate checks it first, the rules can only narrow it further, and a
//! person is never capped.

use pm_policy::{ActionRequest, Actor, Decision, Policy, Roe, Target, Tier};

const SCOPE: &str = "version: 1\nscope:\n  include: [\"http://shop.test/\"]\n";

fn request(actor: &str, tier: Tier) -> ActionRequest {
    ActionRequest {
        actor: Actor::parse(actor).unwrap(),
        action: "replay_send".into(),
        tier,
        target: Some(Target::from_url("http://shop.test/x").unwrap()),
        summary: "x".into(),
    }
}

fn decide(p: &Policy, actor: &str, tier: Tier) -> Decision {
    p.evaluate(&request(actor, tier), jiff::Timestamp::now()).decision
}

#[test]
fn tier_names_round_trip_and_order() {
    for t in Tier::ALL {
        assert_eq!(Tier::parse(t.name()), Some(t));
    }
    assert!(Tier::ALL.windows(2).all(|w| w[0] < w[1]), "lowest first");
}

#[test]
fn the_cap_denies_everything_above_it_and_nothing_below() {
    let p = Policy::new(Roe::parse(SCOPE).unwrap());
    let agent = Actor::parse("agent:claude").unwrap();
    // No cap: the rules decide (agents: safe requests allowed, intrusive ones need approval, destructive denied).
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveSafe), Decision::Allow);
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveIntrusive), Decision::Approve);
    p.set_tier_cap(&agent, Some(Tier::Passive));
    assert_eq!(p.tier_cap(&agent), Some(Tier::Passive));
    assert_eq!(decide(&p, "agent:claude", Tier::Read), Decision::Allow);
    assert_eq!(decide(&p, "agent:claude", Tier::Passive), Decision::Allow);
    for t in [Tier::ActiveSafe, Tier::ActiveIntrusive, Tier::Destructive] {
        let v = p.evaluate(&request("agent:claude", t), jiff::Timestamp::now());
        assert_eq!(v.decision, Decision::Deny, "{t:?}");
        assert!(v.reasons[0].contains("limited to passive"), "{:?}", v.reasons);
    }
    // At active_safe: that and below are the rules' business.
    p.set_tier_cap(&agent, Some(Tier::ActiveSafe));
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveSafe), Decision::Allow);
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveIntrusive), Decision::Deny, "approval cannot lift a cap");
    // Other actors are untouched, a person is never capped, and clearing removes it.
    assert_eq!(decide(&p, "agent:other", Tier::ActiveIntrusive), Decision::Approve);
    p.set_tier_cap(&Actor::parse("human:omkar").unwrap(), Some(Tier::Read));
    assert_eq!(decide(&p, "human:omkar", Tier::ActiveIntrusive), Decision::Allow);
    p.set_tier_cap(&agent, None);
    assert_eq!(p.tier_cap(&agent), None);
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveIntrusive), Decision::Approve);
}

#[test]
fn the_rules_can_only_narrow_a_cap_never_widen_it() {
    // The rules allow an agent everything; a cap still holds.
    let roe =
        Roe::parse(&format!("{SCOPE}tiers:\n  agent:\n    active_intrusive: allow\n    destructive: allow\n")).unwrap();
    let p = Policy::new(roe);
    let agent = Actor::parse("agent:claude").unwrap();
    assert_eq!(decide(&p, "agent:claude", Tier::Destructive), Decision::Allow);
    p.set_tier_cap(&agent, Some(Tier::ActiveIntrusive));
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveIntrusive), Decision::Allow);
    assert_eq!(decide(&p, "agent:claude", Tier::Destructive), Decision::Deny);
    // And rules that deny what the cap allows still deny it.
    let roe = Roe::parse(&format!("{SCOPE}tiers:\n  agent:\n    active_safe: deny\n")).unwrap();
    let p = Policy::new(roe);
    p.set_tier_cap(&agent, Some(Tier::ActiveIntrusive));
    assert_eq!(decide(&p, "agent:claude", Tier::ActiveSafe), Decision::Deny);
    // Swapping the rules keeps the caps.
    p.set_roe(Roe::parse(SCOPE).unwrap());
    assert_eq!(p.tier_cap(&agent), Some(Tier::ActiveIntrusive));
}
