//! `proxymind project lock/unlock`: a sealed project opens only with the
//! passphrase, and a locked file can't be used by accident.

use std::process::Command;

fn pm(dir: &std::path::Path, pass: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_proxymind"))
        .args(["--home", dir.join("home").to_str().unwrap()])
        .args(args)
        .env("PROXYMIND_PASSPHRASE", pass)
        .output()
        .unwrap()
}

#[test]
fn lock_and_unlock_a_project() {
    let dir = std::env::temp_dir().join(format!("pm-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let proj = dir.join("client.pmproj");
    let roe = dir.join("roe.yaml");
    std::fs::write(&roe, "version: 1\nscope:\n  include: [\"https://client.example/\"]\n").unwrap();
    let p = proj.to_str().unwrap();
    assert!(pm(&dir, "", &["-p", p, "roe", "use", roe.to_str().unwrap()]).status.success());
    let pass = "a long enough passphrase";

    let out = pm(&dir, pass, &["-p", p, "project", "lock", "--remove"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let locked = dir.join("client.pmlock");
    assert!(locked.exists() && !proj.exists());
    let bytes = std::fs::read(&locked).unwrap();
    assert!(bytes.starts_with(b"PMLOCK1\0"));
    assert!(!String::from_utf8_lossy(&bytes).contains("client.example"), "nothing readable inside");

    // Using the locked file as a project is refused with a hint.
    let out = pm(&dir, "", &["-p", locked.to_str().unwrap(), "roe", "show"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("project unlock"));

    // Wrong passphrase: refused, and no partial project left behind.
    let out = pm(&dir, "the wrong passphrase", &["project", "unlock", locked.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!proj.exists());
    assert_eq!(
        std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with('.'))
            .count(),
        0
    );

    let out = pm(&dir, pass, &["project", "unlock", locked.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = pm(&dir, "", &["-p", p, "roe", "show"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("client.example"), "the project is back");
    let _ = std::fs::remove_dir_all(&dir);
}
