//! The `ci` actor kind (`proxymind ci`): nobody can approve in a pipeline, so by default it may only send safe
//! requests, and the ROE's `tiers.ci` is the only way to let it do more.

use pm_policy::{ActionRequest, Actor, ActorKind, Decision, Policy, Roe, Target, Tier};

const SCOPE: &str = "version: 1\nscope:\n  include: [\"http://shop.test/\"]\n";

fn decide(roe: &Roe, tier: Tier) -> Decision {
    roe.tier_decision(ActorKind::Ci, tier)
}

#[test]
fn ci_is_an_actor_kind_with_its_own_id() {
    let a = Actor::parse("ci:pipeline").unwrap();
    assert_eq!(a.kind, ActorKind::Ci);
    assert_eq!(a.id(), "ci:pipeline");
    assert!(Actor::parse("ci:").is_err());
    assert!(Actor::parse("ci:bad name").is_err());
}

#[test]
fn defaults_refuse_everything_above_safe_requests() {
    let roe = Roe::parse(SCOPE).unwrap();
    assert_eq!(decide(&roe, Tier::Read), Decision::Allow);
    assert_eq!(decide(&roe, Tier::Passive), Decision::Allow);
    assert_eq!(decide(&roe, Tier::ActiveSafe), Decision::Allow);
    assert_eq!(decide(&roe, Tier::ActiveIntrusive), Decision::Approve, "nobody can approve: the run skips it");
    assert_eq!(decide(&roe, Tier::Destructive), Decision::Deny);
}

#[test]
fn the_rules_name_what_ci_may_do_and_other_kinds_are_unaffected() {
    let roe = Roe::parse(&format!(
        "{SCOPE}tiers:\n  ci:\n    active_intrusive: allow\n  human:\n    destructive: allow\n  agent:\n    active_safe: deny\n"
    ))
    .unwrap();
    assert_eq!(decide(&roe, Tier::ActiveIntrusive), Decision::Allow);
    assert_eq!(decide(&roe, Tier::Destructive), Decision::Deny, "only what the ROE names changes");
    assert_eq!(roe.tier_decision(ActorKind::Human, Tier::Destructive), Decision::Allow);
    assert_eq!(roe.tier_decision(ActorKind::Agent, Tier::ActiveSafe), Decision::Deny);
    assert_eq!(roe.tier_decision(ActorKind::Plugin, Tier::ActiveIntrusive), Decision::Deny);
    // A typo in the section is an error, as for the other kinds.
    assert!(Roe::parse(&format!("{SCOPE}tiers:\n  pipeline:\n    destructive: allow\n")).is_err());
}

#[test]
fn the_gate_never_lets_ci_out_of_scope_whatever_the_tiers_say() {
    let roe =
        Roe::parse(&format!("{SCOPE}tiers:\n  ci:\n    active_intrusive: allow\n    destructive: allow\n")).unwrap();
    let policy = Policy::new(roe);
    let req = |host: &str, tier| ActionRequest {
        actor: Actor::parse("ci:pipeline").unwrap(),
        action: "scan_active".into(),
        tier,
        target: Some(Target::from_parts("http", host, 80, "/").unwrap()),
        summary: "scan".into(),
    };
    let now = jiff::Timestamp::now();
    assert_eq!(policy.evaluate(&req("shop.test", Tier::ActiveIntrusive), now).decision, Decision::Allow);
    assert_eq!(policy.evaluate(&req("other.test", Tier::ActiveIntrusive), now).decision, Decision::Deny);
    assert_eq!(policy.evaluate(&req("shop.test", Tier::ActiveSafe), now).decision, Decision::Allow);
}
