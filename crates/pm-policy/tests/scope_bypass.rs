//! Scope-bypass suite. Every case here is a known trick for getting a
//! request past scope rules. All of them must be refused. Never weaken a
//! test here to make a change pass; fix the change instead.

use pm_policy::{ActionRequest, Actor, Decision, Policy, Roe, Target, Tier};

const ROE: &str = r#"
version: 1
scope:
  include:
    - "https://app.example.com/"
    - "https://api.example.com/v1/"
  exclude:
    - "https://app.example.com/admin"
    - "https://app.example.com/logout"
  deny_networks:
    - "127.0.0.0/8"
    - "169.254.0.0/16"
    - "10.0.0.0/8"
    - "::1/128"
"#;

fn policy() -> Policy {
    Policy::new(Roe::parse(ROE).unwrap())
}

/// A target counts as refused if it can't be parsed or the scope check fails.
fn refused_url(url: &str) -> bool {
    match Target::from_url(url) {
        Err(_) => true,
        Ok(t) => policy().scope_check(&t).is_err(),
    }
}

fn refused_parts(scheme: &str, host: &str, port: u16, path: &str) -> bool {
    match Target::from_parts(scheme, host, port, path) {
        Err(_) => true,
        Ok(t) => policy().scope_check(&t).is_err(),
    }
}

#[test]
fn baseline_in_scope_targets_are_allowed() {
    for url in [
        "https://app.example.com/",
        "https://app.example.com/profile?id=1",
        "https://APP.EXAMPLE.COM/profile",
        "https://app.example.com./profile",
        "https://api.example.com/v1/users",
        "https://app.example.com/administrator-guide", // not under /admin
    ] {
        assert!(!refused_url(url), "should be in scope: {url}");
    }
}

#[test]
fn excluded_paths_cannot_be_reached_by_encoding_or_traversal() {
    for path in [
        "/admin",
        "/admin/",
        "/admin/users",
        "/ADMIN",
        "/Admin/users",
        "/%61dmin",
        "/%2561dmin",
        "/%41DMIN",
        "//admin",
        "/./admin",
        "/profile/../admin",
        "/profile/%2e%2e/admin",
        "/profile/%252e%252e/admin",
        "/profile/..%2fadmin",
        "/profile\\..\\admin",
        "\\admin",
        "/admin;jsessionid=abc",
        "/admin;/users",
        "/admin?x=1",
        "/admin#frag",
        "/logout",
        "/LogOut",
    ] {
        assert!(refused_parts("https", "app.example.com", 443, path), "exclusion bypassed with {path}");
        let url = format!("https://app.example.com{path}");
        assert!(refused_url(&url), "exclusion bypassed with URL {url}");
    }
}

#[test]
fn look_alike_hosts_are_out_of_scope() {
    for url in [
        "https://app.example.com.evil.com/",
        "https://evil.com/app.example.com/",
        "https://appexample.com/",
        "https://app-example.com/",
        "https://example.com/",
        "https://x.app.example.com/",
        "https://app.example.co/",
        "https://app.example.com@evil.com/",
        "https://evil.com@app.example.com/",
        "https://app.example.com:443@evil.com/",
        "https://app.example.com%2eevil.com/",
    ] {
        assert!(refused_url(url), "look-alike host accepted: {url}");
    }
}

#[test]
fn wrong_scheme_or_port_is_out_of_scope() {
    for url in [
        "http://app.example.com/",
        "https://app.example.com:8443/",
        "https://app.example.com:80/",
        "ftp://app.example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ] {
        assert!(refused_url(url), "accepted: {url}");
    }
}

#[test]
fn path_scoped_include_cannot_be_escaped() {
    for url in [
        "https://api.example.com/",
        "https://api.example.com/v2/users",
        "https://api.example.com/v1/../v2/users",
        "https://api.example.com/v1/%2e%2e/v2/users",
        "https://api.example.com/v1x/users",
        "https://api.example.com/V1/users",
    ] {
        assert!(refused_url(url), "escaped path scope: {url}");
    }
}

#[test]
fn denied_networks_win_even_when_the_ip_is_in_scope() {
    // Every IP below is explicitly included, so only deny_networks can stop it.
    let roe = r#"
version: 1
scope:
  include: ["https://127.0.0.1:*/", "https://[::1]:*/", "https://169.254.169.254/", "https://10.0.0.5/"]
  deny_networks: ["127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "::1/128"]
"#;
    let p = Policy::new(Roe::parse(roe).unwrap());
    for host in [
        "127.0.0.1",
        "127.1",
        "0x7f.0.0.1",
        "0x7f000001",
        "2130706433",
        "0177.0.0.1",
        "169.254.169.254",
        "0xa9fea9fe",
        "10.0.0.5",
        "::1",
        "[::1]",
        "::ffff:127.0.0.1",
        "[::ffff:7f00:1]",
    ] {
        let t = Target::from_parts("https", host, 443, "/").unwrap();
        let why = p.scope_check(&t).expect_err(host);
        assert!(why.contains("denied network"), "{host}: refused for the wrong reason: {why}");
    }
    assert!(p.check_resolved(&["::ffff:127.0.0.1".parse().unwrap()]).is_err());
}

#[test]
fn denied_networks_cannot_be_reached_by_ip_tricks() {
    for host in [
        "127.0.0.1",
        "127.1",
        "0x7f.0.0.1",
        "0x7f000001",
        "2130706433",
        "0177.0.0.1",
        "169.254.169.254",
        "0xa9fea9fe",
        "10.0.0.5",
        "::1",
        "[::1]",
        "::ffff:127.0.0.1",
    ] {
        assert!(refused_parts("https", host, 443, "/"), "denied network reachable via {host}");
    }
}

#[test]
fn in_scope_names_resolving_to_denied_networks_are_refused() {
    let p = policy();
    assert!(p.check_resolved(&["93.184.216.34".parse().unwrap()]).is_ok());
    assert!(p.check_resolved(&["93.184.216.34".parse().unwrap(), "127.0.0.1".parse().unwrap()]).is_err());
    assert!(p.check_resolved(&["169.254.169.254".parse().unwrap()]).is_err());
}

#[test]
fn active_actions_without_a_target_are_denied() {
    let req = ActionRequest {
        actor: Actor::parse("human:alice").unwrap(),
        action: "replay_send".into(),
        tier: Tier::ActiveSafe,
        target: None,
        summary: "no target".into(),
    };
    assert_eq!(policy().evaluate(&req, jiff::Timestamp::now()).decision, Decision::Deny);
}

#[test]
fn out_of_scope_is_denied_for_every_actor_and_tier() {
    let target = Target::from_url("https://evil.com/").unwrap();
    for actor in ["human:alice", "agent:claude-1", "plugin:x", "scanner:core"] {
        for tier in [Tier::ActiveSafe, Tier::ActiveIntrusive, Tier::Destructive] {
            let req = ActionRequest {
                actor: Actor::parse(actor).unwrap(),
                action: "replay_send".into(),
                tier,
                target: Some(target.clone()),
                summary: String::new(),
            };
            let v = policy().evaluate(&req, jiff::Timestamp::now());
            assert_eq!(v.decision, Decision::Deny, "{actor} {tier:?}");
        }
    }
}
