//! `proxymind ci` end to end with the real binary against VulnShop: the baseline workflow and exit codes, the
//! outputs (SARIF, JUnit, JSON), unreachable and out-of-scope targets, the rules of engagement (CI never approves),
//! credentials staying out of every file, the budgets, and `--project` not starting anything from a project file.
//!
//! Every run uses the `light` profile and no browser to stay quick.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_proxymind");

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Runs `proxymind ci …` (the demo server needs the test's runtime, so no blocking wait).
async fn ci(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Out {
    let mut cmd = tokio::process::Command::new(BIN);
    cmd.arg("ci")
        .args(args)
        .current_dir(dir)
        .env_remove("PROXYMIND_PROJECT")
        .env_remove("PROXYMIND_HOME")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let o = tokio::time::timeout(std::time::Duration::from_secs(300), cmd.output())
        .await
        .expect("ci run timed out")
        .unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pm-ci-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A ROE for one origin, with limits high enough for a local scan and (with `allow_scan`) the CI tier it needs.
fn write_roe(dir: &Path, origin: &str, allow_scan: bool) -> PathBuf {
    let tiers = if allow_scan { "tiers:\n  ci:\n    active_intrusive: allow\n" } else { "" };
    let path = dir.join(if allow_scan { "roe.yaml" } else { "roe-default.yaml" });
    std::fs::write(
        &path,
        format!(
            "version: 1\nscope:\n  include: [\"{origin}/\"]\nlimits:\n  max_rps_per_host: 2000\n  max_concurrency: 8\n{tiers}"
        ),
    )
    .unwrap();
    path
}

async fn shop() -> String {
    format!("http://127.0.0.1:{}", pm_demo::VulnShop::start_local().await.unwrap().port())
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// SARIF 2.1.0 as far as code scanning dashboards care: the required fields, one rule per result id, the CI
/// fingerprint on every result, and a baseline state from the allowed set.
fn validate_sarif(v: &Value) {
    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif"));
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    assert_eq!(run["tool"]["driver"]["name"], "ProxyMind");
    assert!(run["tool"]["driver"]["version"].is_string());
    let rules: Vec<&str> =
        run["tool"]["driver"]["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    for r in run["tool"]["driver"]["rules"].as_array().unwrap() {
        assert!(r["shortDescription"]["text"].is_string(), "{r}");
    }
    let mut fingerprints = std::collections::BTreeSet::new();
    for r in run["results"].as_array().unwrap() {
        assert!(rules.contains(&r["ruleId"].as_str().unwrap()), "result without a rule: {r}");
        assert!(["error", "warning", "note"].contains(&r["level"].as_str().unwrap()), "{r}");
        assert!(r["message"]["text"].as_str().is_some_and(|t| !t.is_empty()));
        assert!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str().is_some_and(|u| !u.is_empty())
        );
        let fp = r["partialFingerprints"]["proxymindFingerprint/v1"].as_str().expect("partialFingerprints");
        assert!(fp.len() == 32 && fp.chars().all(|c| c.is_ascii_hexdigit()), "{fp}");
        assert!(fingerprints.insert(fp.to_string()), "two results with one fingerprint");
        assert_eq!(r["partialFingerprints"].as_object().unwrap().len(), 1, "only the stable fingerprint");
        assert!(["new", "unchanged", "absent"].contains(&r["baselineState"].as_str().unwrap()), "{r}");
    }
    assert!(run["invocations"][0]["executionSuccessful"].is_boolean());
    assert!(run["invocations"][0]["exitCode"].is_number());
}

/// A small well-formedness check for the JUnit file: balanced tags, quoted attributes, known entities only.
fn assert_well_formed_xml(x: &str) {
    assert!(x.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    let mut stack: Vec<String> = Vec::new();
    let mut rest = &x[x.find("?>").unwrap() + 2..];
    let mut roots = 0;
    while let Some(i) = rest.find('<') {
        check_text(&rest[..i]);
        let end = rest[i..].find('>').expect("unterminated tag") + i;
        // `>` can appear inside attribute values only escaped, so the first one ends the tag.
        let tag = &rest[i + 1..end];
        rest = &rest[end + 1..];
        if let Some(name) = tag.strip_prefix('/') {
            assert_eq!(stack.pop().as_deref(), Some(name.trim()), "mismatched closing tag {tag}");
            continue;
        }
        let self_closing = tag.ends_with('/');
        let body = tag.trim_end_matches('/');
        let name = body.split_whitespace().next().unwrap();
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "bad tag name {name}");
        let mut attrs = body[name.len()..].trim();
        while !attrs.is_empty() {
            let eq = attrs.find('=').expect("attribute without a value");
            assert!(attrs[..eq].trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':'));
            let after = attrs[eq + 1..].trim_start();
            assert!(after.starts_with('"'), "unquoted attribute in {tag}");
            let close = after[1..].find('"').expect("unterminated attribute") + 1;
            check_text(&after[1..close]);
            assert!(!after[1..close].contains('<'));
            attrs = after[close + 1..].trim_start();
        }
        if stack.is_empty() {
            roots += 1;
        }
        if !self_closing {
            stack.push(name.to_string());
        }
    }
    check_text(rest);
    assert!(stack.is_empty(), "unclosed tags {stack:?}");
    assert_eq!(roots, 1);
}

fn check_text(t: &str) {
    assert!(!t.contains('<') && !t.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r')), "{t:?}");
    for (i, _) in t.match_indices('&') {
        let ent = &t[i..];
        assert!(
            ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"].iter().any(|e| ent.starts_with(e)),
            "bad entity in {t:?}"
        );
    }
}

fn proven_fingerprints(summary: &Value) -> Vec<String> {
    summary["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["status"] == "proven")
        .map(|f| f["fingerprint"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn baseline_workflow_and_outputs() {
    let origin = shop().await;
    let dir = temp_dir("baseline");
    let roe = write_roe(&dir, &origin, true);
    let base = ["--roe", s(&roe), "--target", &format!("{origin}/"), "--profile", "light", "--no-browser"];
    let with = |extra: &[&str]| -> Vec<String> { base.iter().chain(extra.iter()).map(|x| x.to_string()).collect() };
    let run = |extra: Vec<String>| {
        let dir = dir.clone();
        async move {
            let refs: Vec<&str> = extra.iter().map(String::as_str).collect();
            ci(&dir, &refs, &[]).await
        }
    };

    // 1. First run, no baseline: proven findings exist, so it fails, and writes the baseline and every output.
    let (b, sarif, junit, json_out) =
        (dir.join("baseline.json"), dir.join("a.sarif"), dir.join("a.xml"), dir.join("a.json"));
    let r = run(with(&[
        "--write-baseline",
        s(&b),
        "--baseline-suspected",
        "--sarif",
        s(&sarif),
        "--junit",
        s(&junit),
        "--json",
        s(&json_out),
    ]))
    .await;
    assert_eq!(r.code, 1, "{}", r.all());
    assert!(r.stdout.contains("FAIL") && r.stdout.contains("exit code 1"), "{}", r.stdout);
    let summary = read_json(&json_out);
    assert_eq!(summary["format"], "proxymind-ci-1");
    assert_eq!(summary["complete"], true, "{summary}");
    assert_eq!(summary["tls_verified"], true);
    assert_eq!(summary["actor"], "ci:pipeline");
    let proven = proven_fingerprints(&summary);
    assert!(!proven.is_empty(), "VulnShop's error-based SQL injection should be proven: {summary}");
    assert_eq!(summary["counts"]["new"], summary["counts"]["total"], "no baseline: everything is new");
    assert!(summary["requests"].as_u64().unwrap() > 10);
    assert!(
        summary["findings"].as_array().unwrap().iter().any(|f| f["issue"] == "sqli" && f["path"] == "/api/recommend")
    );
    validate_sarif(&read_json(&sarif));
    assert_well_formed_xml(&std::fs::read_to_string(&junit).unwrap());
    let baseline = read_json(&b);
    assert_eq!(baseline["format"], "proxymind-ci-baseline-1");
    assert_eq!(baseline["fingerprint_version"], 1);
    let entries = baseline["findings"].as_array().unwrap().clone();
    assert_eq!(
        entries.len(),
        summary["findings"].as_array().unwrap().len(),
        "--baseline-suspected keeps suspected ones"
    );
    // Fingerprints carry no ids or times: the key is readable and stable.
    for e in &entries {
        assert!(e["key"].as_str().unwrap().starts_with("v1|"), "{e}");
    }

    // 2. Second run against the baseline: nothing new, so it passes (the SARIF now says "unchanged").
    let sarif2 = dir.join("b.sarif");
    let json2 = dir.join("b.json");
    let r = run(with(&["--baseline", s(&b), "--sarif", s(&sarif2), "--json", s(&json2)])).await;
    assert_eq!(r.code, 0, "{}", r.all());
    let summary2 = read_json(&json2);
    assert_eq!(summary2["counts"]["new"], 0, "{summary2}");
    assert_eq!(summary2["counts"]["failing"], 0);
    assert!(summary2["counts"]["unchanged"].as_u64().unwrap() >= 1);
    let sarif2 = read_json(&sarif2);
    validate_sarif(&sarif2);
    assert!(sarif2["runs"][0]["results"].as_array().unwrap().iter().all(|r| r["baselineState"] != "new"));
    // The same fingerprints as the first run: they do not depend on the project, ids or time.
    let fps2: Vec<String> = summary2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["fingerprint"].as_str().unwrap().to_string())
        .collect();
    for fp in &fps2 {
        assert!(entries.iter().any(|e| e["fingerprint"] == json!(fp)), "{fp} is not in the first run's baseline");
    }

    // 3. Take one proven entry out of the baseline: exactly that finding is new, and fails the run.
    let removed = &proven[0];
    let mut edited = baseline.clone();
    edited["findings"].as_array_mut().unwrap().retain(|e| e["fingerprint"] != json!(removed));
    let b3 = dir.join("baseline-3.json");
    std::fs::write(&b3, serde_json::to_string_pretty(&edited).unwrap()).unwrap();
    let json3 = dir.join("c.json");
    let sarif3 = dir.join("c.sarif");
    let r = run(with(&["--baseline", s(&b3), "--json", s(&json3), "--sarif", s(&sarif3)])).await;
    assert_eq!(r.code, 1, "{}", r.all());
    let summary3 = read_json(&json3);
    let new: Vec<&str> = summary3["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["state"] == "new")
        .map(|f| f["fingerprint"].as_str().unwrap())
        .collect();
    assert_eq!(new, vec![removed.as_str()], "{summary3}");
    assert_eq!(summary3["counts"]["failing"], 1);
    let sarif3 = read_json(&sarif3);
    let states: Vec<(&str, &str)> = sarif3["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["partialFingerprints"]["proxymindFingerprint/v1"].as_str().unwrap(),
                r["baselineState"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(states.contains(&(removed.as_str(), "new")), "{states:?}");

    // 4. A baseline entry this run does not find again is "fixed": reported, never failing.
    let mut with_gone = baseline.clone();
    with_gone["findings"].as_array_mut().unwrap().push(json!({
        "fingerprint": "00000000000000000000000000000001", "key": "v1|idor|GET|/api/gone/{id}|", "issue": "idor",
        "method": "GET", "path": "/api/gone/{id}", "point": "", "severity": "high", "status": "proven", "title": "gone"
    }));
    let b4 = dir.join("baseline-4.json");
    std::fs::write(&b4, serde_json::to_string_pretty(&with_gone).unwrap()).unwrap();
    let (json4, sarif4, junit4) = (dir.join("d.json"), dir.join("d.sarif"), dir.join("d.xml"));
    let r = run(with(&["--baseline", s(&b4), "--json", s(&json4), "--sarif", s(&sarif4), "--junit", s(&junit4)])).await;
    assert_eq!(r.code, 0, "{}", r.all());
    assert_eq!(read_json(&json4)["counts"]["fixed"], 1);
    assert!(r.stdout.contains("fixed? GET /api/gone/{id}"), "{}", r.stdout);
    let sarif4 = read_json(&sarif4);
    validate_sarif(&sarif4);
    assert!(
        sarif4["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["baselineState"] == "absent" && r["ruleId"] == "idor")
    );
    let junit4 = std::fs::read_to_string(&junit4).unwrap();
    assert_well_formed_xml(&junit4);
    assert!(junit4.contains("proxymind.fixed"));

    // 5. The gate options: `--fail-on none` and a high `--min-severity` do not fail a run with findings.
    let r = run(with(&["--fail-on", "none"])).await;
    assert_eq!(r.code, 0, "{}", r.all());
    let r = run(with(&["--min-severity", "critical"])).await;
    assert_eq!(r.code, 0, "{}", r.all());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_target_is_exit_2_never_clean() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://127.0.0.1:{}", l.local_addr().unwrap().port())
    };
    let dir = temp_dir("dead");
    let roe = write_roe(&dir, &dead, true);
    let (sarif, junit, json_out) = (dir.join("o.sarif"), dir.join("o.xml"), dir.join("o.json"));
    let r = ci(
        &dir,
        &[
            "--roe",
            s(&roe),
            "--profile",
            "light",
            "--no-browser",
            "--sarif",
            s(&sarif),
            "--junit",
            s(&junit),
            "--json",
            s(&json_out),
        ],
        &[],
    )
    .await;
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(
        r.stdout.contains("INCOMPLETE: the target is not reachable") && r.stdout.contains("NOT CLEAN"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("PASS"));
    let summary = read_json(&json_out);
    assert_eq!(summary["complete"], false);
    assert_eq!(summary["exit_code"], 2);
    // The outputs exist even so (a pipeline uploads them with `if: always()`), and say the run failed.
    let sarif = read_json(&sarif);
    validate_sarif(&sarif);
    assert_eq!(sarif["runs"][0]["invocations"][0]["executionSuccessful"], false);
    let junit = std::fs::read_to_string(&junit).unwrap();
    assert_well_formed_xml(&junit);
    assert!(junit.contains("errors=\"2\"") || junit.contains("errors=\"1\""), "{junit}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_outside_the_scope_is_an_error_and_nothing_is_sent() {
    let origin = shop().await;
    let dir = temp_dir("scope");
    // The ROE covers another port: the target below is not in scope.
    let roe = write_roe(&dir, "http://127.0.0.1:9", true);
    let json_out = dir.join("o.json");
    let r = ci(&dir, &["--roe", s(&roe), "--target", &format!("{origin}/"), "--json", s(&json_out)], &[]).await;
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(r.stderr.contains("not allowed by the rules of engagement"), "{}", r.stderr);
    assert!(!json_out.exists(), "no run happened, so no result file");
    // A ROE that does not parse is an error as well, and so is one that is missing.
    std::fs::write(dir.join("bad.yaml"), "version: 1\nscope: {}\n").unwrap();
    assert_eq!(ci(&dir, &["--roe", "bad.yaml", "--target", &origin], &[]).await.code, 2);
    assert_eq!(ci(&dir, &["--roe", "missing.yaml", "--target", &origin], &[]).await.code, 2);
    // The ROE is required: no flag, no run (the usage error is exit 2 too).
    assert_eq!(ci(&dir, &["--target", &origin], &[]).await.code, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_never_approves_what_the_rules_leave_to_a_person() {
    let origin = shop().await;
    let dir = temp_dir("approve");
    // No tiers.ci: CI may send safe requests, and scan probes need an approval nobody can give.
    let roe = write_roe(&dir, &origin, false);
    let json_out = dir.join("o.json");
    let r = ci(&dir, &["--roe", s(&roe), "--profile", "light", "--no-browser", "--json", s(&json_out)], &[]).await;
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(
        r.stdout.contains("tiers.ci.active_intrusive") && r.stdout.contains("skipped by the rules of engagement"),
        "{}",
        r.stdout
    );
    let summary = read_json(&json_out);
    assert_eq!(summary["findings"].as_array().unwrap().len(), 0, "nothing was scanned, so nothing was found");
    assert!(!summary["skipped"].as_array().unwrap().is_empty());
    // --allow-skipped accepts the skip but the run still says what it did not do.
    let r = ci(
        &dir,
        &["--roe", s(&roe), "--profile", "light", "--no-browser", "--allow-skipped", "--json", s(&json_out)],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(r.stdout.contains("skipped by the rules of engagement"), "{}", r.stdout);
    // An explicit refusal for CI is a skip as well.
    std::fs::write(
        dir.join("deny.yaml"),
        format!("version: 1\nscope:\n  include: [\"{origin}/\"]\ntiers:\n  ci:\n    active_intrusive: deny\n"),
    )
    .unwrap();
    let r = ci(&dir, &["--roe", "deny.yaml", "--profile", "light", "--no-browser"], &[]).await;
    assert_eq!(r.code, 2, "{}", r.all());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_budget_is_a_hard_cap_and_a_spent_budget_is_exit_2() {
    let origin = shop().await;
    let dir = temp_dir("budget");
    let roe = write_roe(&dir, &origin, true);
    let json_out = dir.join("o.json");
    let r = ci(
        &dir,
        &["--roe", s(&roe), "--profile", "light", "--no-browser", "--max-requests", "25", "--json", s(&json_out)],
        &[],
    )
    .await;
    assert_eq!(r.code, 2, "{}", r.all());
    let summary = read_json(&json_out);
    assert!(summary["requests"].as_u64().unwrap() <= 25, "{summary}");
    assert_eq!(summary["complete"], false);
    assert!(
        summary["incomplete"].as_array().unwrap().iter().any(|m| m.as_str().unwrap().contains("budget")),
        "{summary}"
    );
    // A time budget of no minutes is spent before the first request.
    let r = ci(
        &dir,
        &["--roe", s(&roe), "--profile", "light", "--no-browser", "--budget-minutes", "0", "--json", s(&json_out)],
        &[],
    )
    .await;
    assert_eq!(r.code, 2, "{}", r.all());
    assert_eq!(read_json(&json_out)["requests"], 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_come_from_the_environment_and_never_reach_a_file_or_the_screen() {
    let origin = shop().await;
    let dir = temp_dir("secrets");
    let roe = write_roe(&dir, &origin, true);
    let login_body = r#"{"username":"alice","password":"${PM_CI_TEST_PASSWORD}"}"#;
    let ident = json!({
        "name": "alice", "role": "user",
        "login": { "steps": [{ "url": origin, "request": format!(
            "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n{login_body}") }] },
        "health": { "url": origin, "request": "GET /api/me HTTP/1.1\r\nHost: x\r\n\r\n", "expect_status": 200 },
    });
    std::fs::write(dir.join("alice.json"), serde_json::to_string_pretty(&ident).unwrap()).unwrap();
    let args = |extra: &[&str]| -> Vec<String> {
        [
            "--roe",
            s(&roe),
            "--profile",
            "light",
            "--no-browser",
            "--identity-file",
            s(&dir.join("alice.json")),
            "--identity",
            "alice",
        ]
        .iter()
        .chain(extra)
        .map(|x| x.to_string())
        .collect()
    };
    let (sarif, junit, json_out, baseline) =
        (dir.join("o.sarif"), dir.join("o.xml"), dir.join("o.json"), dir.join("b.json"));
    let a = args(&[
        "--sarif",
        s(&sarif),
        "--junit",
        s(&junit),
        "--json",
        s(&json_out),
        "--write-baseline",
        s(&baseline),
        "--baseline-suspected",
    ]);
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let r = ci(&dir, &refs, &[("PM_CI_TEST_PASSWORD", "alice123")]).await;
    assert_eq!(r.code, 1, "{}", r.all());
    let summary = read_json(&json_out);
    assert!(
        summary["checks"].as_array().unwrap().iter().any(|c| c["name"] == "login alice" && c["outcome"] == "passed"),
        "{summary}"
    );
    // Nothing the run wrote or printed holds the password (or the session it got).
    let mut everything = r.all();
    for f in [&sarif, &junit, &json_out, &baseline] {
        everything.push_str(&std::fs::read_to_string(f).unwrap());
    }
    assert!(!everything.contains("alice123"), "the password leaked");
    assert!(!everything.to_lowercase().contains("session="), "a session cookie leaked");

    // A wrong password: the login fails, so the run is not clean, and the wrong value is not printed either.
    let a = args(&["--json", s(&json_out)]);
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let r = ci(&dir, &refs, &[("PM_CI_TEST_PASSWORD", "wrongpw-8472")]).await;
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(r.stdout.contains("INCOMPLETE: login as alice failed"), "{}", r.stdout);
    assert!(!r.all().contains("wrongpw-8472") && !std::fs::read_to_string(&json_out).unwrap().contains("wrongpw-8472"));

    // A variable that is not set is an error before anything is sent.
    let a = args(&[]);
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let r = ci(&dir, &refs, &[]).await;
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(r.stderr.contains("PM_CI_TEST_PASSWORD is not set"), "{}", r.stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_baseline_is_an_error_and_help_documents_the_exit_codes() {
    let origin = shop().await;
    let dir = temp_dir("badbase");
    let roe = write_roe(&dir, &origin, true);
    let r = ci(&dir, &["--roe", s(&roe), "--baseline", "nope.json"], &[]).await;
    assert_eq!(r.code, 2, "{}", r.all());
    std::fs::write(
        dir.join("old.json"),
        r#"{"format":"proxymind-ci-baseline-1","fingerprint_version":7,"findings":[]}"#,
    )
    .unwrap();
    let r = ci(&dir, &["--roe", s(&roe), "--baseline", "old.json"], &[]).await;
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("fingerprint version 7"), "{}", r.stderr);
    let help = ci(&dir, &["--help"], &[]).await;
    assert_eq!(help.code, 0);
    for needle in
        ["EXIT CODES", "--fail-on", "--min-severity", "--write-baseline", "--budget-minutes", "--insecure", "tiers.ci"]
    {
        assert!(help.stdout.contains(needle), "--help lacks {needle}:\n{}", help.stdout);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A project file is active content (threat model F-2): with `--project`, a saved listener, upstream proxy, session
/// rule and schedule must have no effect on a CI run, and the ROE file given on the command line must not be written
/// into the project.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_project_file_cannot_start_listeners_or_steer_the_run() {
    use pm_service::pm_policy::{Actor, Policy, Roe};
    use pm_service::pm_store::Store;
    use pm_service::{
        Every, SESSION_SETTING, ScanSchedule, ScanTaskRequest, Service, SessionConfig, SessionRule, SetValue,
    };

    let origin = shop().await;
    let dir = temp_dir("project");
    let project = dir.join("saved.pmproj");
    let listener_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let schedule_id;
    {
        let mut store = Store::open(&project).unwrap();
        // Everything a hostile or careless project file could carry.
        store
            .set_setting(
                pm_service::LISTENERS_SETTING,
                &json!([{ "bind": format!("127.0.0.1:{listener_port}"), "enabled": true }]).to_string(),
            )
            .unwrap();
        // Every request through a dead upstream proxy: honoured, the run could not reach the target at all.
        store
            .set_setting(
                pm_service::NETWORK_SETTING,
                &json!({ "upstream_rules": [{ "via": "http://127.0.0.1:1" }] }).to_string(),
            )
            .unwrap();
        let session = SessionConfig {
            rules: vec![SessionRule {
                name: "inject".into(),
                set: vec![SetValue { name: "X-Injected-By-Project".into(), value: "yes".into(), ..Default::default() }],
                ..Default::default()
            }],
            saved_by: "human:someone".into(),
            ..Default::default()
        };
        store.set_setting(SESSION_SETTING, &serde_json::to_string(&session).unwrap()).unwrap();
        let roe = Roe::parse(&format!("version: 1\nscope:\n  include: [\"{origin}/\"]\n")).unwrap();
        let service = Service::new(store, Policy::new(roe)).unwrap();
        let human = Actor::parse("human:someone").unwrap();
        schedule_id = service
            .schedule_save(
                &human,
                ScanSchedule {
                    name: "nightly".into(),
                    every: Every::Hourly,
                    enabled: true,
                    request: ScanTaskRequest { url: format!("{origin}/"), ..Default::default() },
                    ..Default::default()
                },
            )
            .unwrap()
            .id;
    }
    let roe = write_roe(&dir, &origin, true);
    let json_out = dir.join("o.json");
    let r = ci(
        &dir,
        &["--roe", s(&roe), "--profile", "light", "--no-browser", "--project", s(&project), "--json", s(&json_out)],
        &[],
    )
    .await;
    assert_eq!(r.code, 1, "the run reached the target despite the saved upstream proxy: {}", r.all());
    assert!(r.stderr.contains("are not started") && r.stderr.contains("ignored"), "{}", r.stderr);
    assert!(read_json(&json_out)["complete"] == true);
    // The saved listener was not started.
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", listener_port)).is_err(),
        "a listener from the project file is running"
    );
    // Reopen: the data is kept in the project, nothing of the project's steered the requests, the ROE is untouched.
    let store = Store::open(&project).unwrap();
    assert!(store.get_setting("roe").unwrap().is_none(), "the CI ROE file must not be written into the project");
    let roe = Roe::parse(&format!("version: 1\nscope:\n  include: [\"{origin}/\"]\n")).unwrap();
    let service = std::sync::Arc::new(Service::new(store, Policy::new(roe)).unwrap());
    let human = Actor::parse("human:someone").unwrap();
    let history = service
        .history_search(&human, &pm_service::pm_store::HistoryFilter { limit: Some(500), ..Default::default() })
        .unwrap()
        .exchanges;
    assert!(!history.is_empty(), "the CI run's traffic is recorded in the project");
    for h in &history {
        let ex = service.exchange_raw(h.id).unwrap();
        let req = String::from_utf8_lossy(&ex.request).to_lowercase();
        assert!(!req.contains("x-injected-by-project"), "a session rule from the project file was applied");
    }
    assert!(history.iter().all(|h| h.source != "macro"));
    let schedule = service.schedule_list().unwrap().into_iter().find(|x| x.id == schedule_id).unwrap();
    assert!(schedule.last_run_ms.is_none() && schedule.last_task.is_none(), "a schedule from the project ran");
    assert!(
        service.scan_task_list(&human).iter().all(|t| t.schedule_id.is_none() && t.actor == "ci:pipeline"),
        "only the CI run's own scan task exists"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A profile that asks for the checks needing the destructive tier (smuggling, uploads, races): CI leaves them out
/// and says so, and no approval is ever granted on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_only_checks_are_left_out_and_nothing_is_approved() {
    use pm_service::pm_policy::{Actor, Policy, Roe};
    use pm_service::pm_store::Store;
    use pm_service::{ScanProfile, Service};

    let origin = shop().await;
    let dir = temp_dir("destructive");
    let project = dir.join("p.pmproj");
    {
        let roe = Roe::parse(&format!("version: 1\nscope:\n  include: [\"{origin}/\"]\n")).unwrap();
        let service = Service::new(Store::open(&project).unwrap(), Policy::new(roe)).unwrap();
        service
            .scan_profile_save(
                &Actor::parse("human:someone").unwrap(),
                ScanProfile {
                    name: "small-thorough".into(),
                    approval_checks: true,
                    max_pages: Some(3),
                    max_targets: Some(3),
                    max_requests: Some(25),
                    browser: Some(false),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let roe = write_roe(&dir, &origin, true);
    let json_out = dir.join("o.json");
    let r = ci(
        &dir,
        &["--roe", s(&roe), "--profile", "small-thorough", "--project", s(&project), "--json", s(&json_out)],
        &[],
    )
    .await;
    // New proven findings outrank an unfinished run (exit 1), and the file says it did not finish.
    assert_eq!(r.code, 1, "{}", r.all());
    assert_eq!(read_json(&json_out)["complete"], false);
    assert!(r.stdout.contains("request smuggling, file upload and race checks"), "{}", r.stdout);
    let summary = read_json(&json_out);
    assert!(
        summary["skipped"].as_array().unwrap().iter().any(|m| m.as_str().unwrap().contains("destructive tier")),
        "{summary}"
    );
    let service = Service::new(
        Store::open(&project).unwrap(),
        Policy::new(Roe::parse(&format!("version: 1\nscope:\n  include: [\"{origin}/\"]\n")).unwrap()),
    )
    .unwrap();
    assert!(service.approvals(Some("approved"), 100).unwrap().is_empty(), "CI must never approve anything");
    // Accepting the skip turns the exit code into the findings' verdict.
    let r =
        ci(&dir, &["--roe", s(&roe), "--profile", "small-thorough", "--project", s(&project), "--allow-skipped"], &[])
            .await;
    assert!(r.code == 0 || r.code == 1, "{}", r.all());
    let _ = std::fs::remove_dir_all(&dir);
}
