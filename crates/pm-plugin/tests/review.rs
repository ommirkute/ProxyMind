//! Installing, updating and accepting permissions of v2 plugins (ADR-0020).

use pm_plugin::Registry;
use pm_plugin::v2::HookKind;

fn write(dir: &std::path::Path, perms: &str) {
    std::fs::write(
        dir.join("proxymind-plugin.yaml"),
        format!(
            "name: rv\nversion: 1\napi: 2\npermissions: {perms}\nhooks:\n  request:\n    command: [\"python3\", \"h.py\"]\n"
        ),
    )
    .unwrap();
}

#[test]
fn changed_permissions_keep_the_plugin_off_until_accepted() {
    let home = std::env::temp_dir().join(format!("pm-review-{}", std::process::id()));
    let dir = home.join("p");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("h.py"), "pass\n").unwrap();
    write(&dir, "[hooks.request]");

    let mut reg = Registry::load(&home).unwrap();
    reg.add(&dir).unwrap();
    assert!(!reg.find("rv").unwrap().enabled && reg.needs_review("rv"), "fresh v2 installs wait for review");
    assert!(reg.set_enabled_checked("rv", true).is_err());
    assert_eq!(reg.effective_permissions("rv"), Some(vec![]));
    assert!(reg.hook_blocker("rv", HookKind::Request).is_some());
    reg.accept_permissions("rv").unwrap();
    reg.set_hook_on("rv", HookKind::Request, true);
    reg.save().unwrap();
    assert!(reg.hook_blocker("rv", HookKind::Request).is_none());
    assert_eq!(reg.active_hooks().len(), 1);

    // Reinstalling with the same permissions keeps it on.
    let mut reg = Registry::load(&home).unwrap();
    reg.add(&dir).unwrap();
    assert!(reg.find("rv").unwrap().enabled && !reg.needs_review("rv"));
    assert_eq!(reg.active_hooks().len(), 1);

    // An update that asks for more: off again, hooks don't run, until accepted.
    write(&dir, "[hooks.request, history.read]");
    reg.add(&dir).unwrap();
    assert!(!reg.find("rv").unwrap().enabled && reg.needs_review("rv"));
    assert!(reg.active_hooks().is_empty());
    reg.save().unwrap();
    let mut reg = Registry::load(&home).unwrap();
    assert!(reg.needs_review("rv") && reg.active_hooks().is_empty(), "stored");
    assert_eq!(reg.accept_permissions("rv").unwrap(), ["history.read", "hooks.request"]);
    assert_eq!(reg.active_hooks().len(), 1, "the hook was turned on before and stays on");

    // Removing forgets the state.
    assert!(reg.remove("rv"));
    assert!(reg.state.accepted.is_empty() && reg.state.hooks_on.is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn hooks_keep_the_order_a_person_sets() {
    let home = std::env::temp_dir().join(format!("pm-order-{}", std::process::id()));
    let mut reg = Registry::load(&home).unwrap();
    for n in ["aa", "bb", "cc"] {
        let dir = home.join(n);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("h.py"), "pass\n").unwrap();
        std::fs::write(
            dir.join("proxymind-plugin.yaml"),
            format!(
                "name: {n}\nversion: 1\napi: 2\npermissions: [hooks.request]\nhooks:\n  request:\n    command: [x]\n"
            ),
        )
        .unwrap();
        reg.add(&dir).unwrap();
    }
    let names = |r: &Registry| r.hooks_in_order().into_iter().map(|h| h.0).collect::<Vec<_>>();
    assert_eq!(names(&reg), ["aa", "bb", "cc"]);
    reg.move_hook("cc", HookKind::Request, -1).unwrap();
    assert_eq!(names(&reg), ["aa", "cc", "bb"]);
    reg.move_hook("cc", HookKind::Request, -1).unwrap();
    reg.move_hook("cc", HookKind::Request, -1).unwrap(); // already first: no change
    assert_eq!(names(&reg), ["cc", "aa", "bb"]);
    reg.move_hook("cc", HookKind::Request, 1).unwrap();
    assert_eq!(names(&reg), ["aa", "cc", "bb"]);
    let _ = std::fs::remove_dir_all(&home);
}
