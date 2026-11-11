//! Proven findings as regression tests a developer's CI runs: see
//! `pm_tools::regress` for the format. Export builds a test per proven
//! finding (differential authorization, reflection, timing); the runner
//! sends them to the origin they came from or a `--target`, with
//! credentials from the environment, and says which findings are still
//! there. The runner needs no project and sends only to that one origin.

use std::time::Duration;

use pm_policy::{Actor, ActorKind};
use pm_tools::regress::{self, FORMAT, RegressionTest, TestFinding, VulnerableIf};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub finding_id: i64,
    pub title: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegressionExport {
    pub tests: Vec<RegressionTest>,
    /// Findings with no test, and why.
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegressionResult {
    pub finding_id: i64,
    pub title: String,
    /// vulnerable (still there), fixed, skipped (e.g. credentials not set) or error
    pub outcome: String,
    pub detail: String,
    pub elapsed_ms: u64,
}

fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let port = u.port_or_known_default()?;
    Some(format!("{}://{}:{port}", u.scheme(), u.host_str()?))
}

impl Service {
    /// The credential headers an identity uses (to strip from recorded requests).
    fn auth_header_names(&self, identity: &str) -> Vec<String> {
        let Ok(id) = self.load_identity(identity) else { return vec!["cookie".into(), "authorization".into()] };
        let mut names: Vec<String> = id.auth.headers.iter().map(|(h, _)| h.to_ascii_lowercase()).collect();
        if !id.auth.cookies.is_empty() {
            names.push("cookie".into());
        }
        names.push("authorization".into());
        names.sort();
        names.dedup();
        names
    }

    fn with_identity(&self, raw: &str, identity: Option<&str>) -> (String, Vec<String>) {
        match identity.filter(|i| !i.is_empty() && *i != pm_identity::ANONYMOUS) {
            Some(i) => (regress::strip_auth(raw, &self.auth_header_names(i), i), vec![i.to_string()]),
            None => (raw.to_string(), vec![]),
        }
    }

    /// A regression test for each proven finding, and why the others have none.
    pub fn regression_tests(&self) -> Result<RegressionExport> {
        let mut out = RegressionExport { tests: vec![], skipped: vec![] };
        for f in self.finding_list(None)? {
            let id = f["id"].as_i64().unwrap_or(0);
            let title = f["title"].as_str().unwrap_or_default().to_string();
            if f["status"] == "false_positive" {
                continue;
            }
            let skip = |reason: &str| Skipped { finding_id: id, title: title.clone(), reason: reason.into() };
            let proofs = self.proofs_for_finding(id)?;
            let Some(p) = proofs.iter().find(|p| p["proven"] == true) else {
                out.skipped.push(skip("no proof yet: prove it in ProxyMind (proof_run) first"));
                continue;
            };
            let finding = TestFinding {
                id,
                title: title.clone(),
                severity: f["severity"].as_str().unwrap_or_default().into(),
                vuln_class: f["vuln_class"].as_str().unwrap_or_default().into(),
                url: f["url"].as_str().unwrap_or_default().into(),
            };
            let (d, inputs) = (&p["details"], &p["inputs"]);
            let exchange = |eid: Option<i64>| -> Option<(String, String)> {
                let ex = self.store.lock().get_exchange(eid?).ok()??;
                let s = &ex.summary;
                Some((
                    String::from_utf8_lossy(&ex.request).into_owned(),
                    format!("{}://{}:{}", s.scheme, s.host, s.port),
                ))
            };
            let identity = inputs["identity"].as_str();
            let test = match p["oracle"].as_str().unwrap_or_default() {
                "differential_authz" => {
                    let attacker = d["attacker"].as_str().unwrap_or_default();
                    match exchange(d["exchanges"]["attacker"].as_i64()) {
                        None => Err("the attacker's exchange is no longer in the project"),
                        Some((raw, origin)) => {
                            let (request, auth) = self.with_identity(&raw, Some(attacker));
                            let markers: Vec<String> = d["markers_found"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect();
                            Ok(RegressionTest {
                                format: FORMAT.into(),
                                finding,
                                origin,
                                oracle: "differential_authz".into(),
                                request,
                                baseline: None,
                                auth,
                                vulnerable_if: VulnerableIf {
                                    status_min: Some(200),
                                    status_max: Some(299),
                                    body_contains_any: markers,
                                    ..Default::default()
                                },
                                samples: 1,
                            })
                        }
                    }
                }
                "reflection" => match (inputs["raw"].as_str(), d["url"].as_str().and_then(origin_of)) {
                    (Some(raw), Some(origin)) => {
                        let (request, auth) = self.with_identity(raw, identity);
                        Ok(RegressionTest {
                            format: FORMAT.into(),
                            finding,
                            origin,
                            oracle: "reflection".into(),
                            request,
                            baseline: None,
                            auth,
                            vulnerable_if: VulnerableIf { reflects_payload: true, ..Default::default() },
                            samples: 1,
                        })
                    }
                    _ => Err("the proof's request template is missing"),
                },
                "timing" => {
                    let from_ex = exchange(inputs["exchange_id"].as_i64());
                    let origin =
                        from_ex.as_ref().map(|x| x.1.clone()).or_else(|| inputs["url"].as_str().and_then(origin_of));
                    let baseline = inputs["baseline_raw"].as_str().map(str::to_string).or(from_ex.map(|x| x.0));
                    match (inputs["payload_raw"].as_str(), baseline, origin) {
                        (Some(payload), Some(baseline), Some(origin)) => {
                            let (request, auth) = self.with_identity(payload, identity);
                            let (baseline, _) = self.with_identity(&baseline, identity);
                            Ok(RegressionTest {
                                format: FORMAT.into(),
                                finding,
                                origin,
                                oracle: "timing".into(),
                                request,
                                baseline: Some(baseline),
                                auth,
                                vulnerable_if: VulnerableIf {
                                    slower_by_ms: Some(inputs["min_effect_ms"].as_f64().unwrap_or(500.0)),
                                    ..Default::default()
                                },
                                samples: 5,
                            })
                        }
                        _ => Err("the proof's requests are missing"),
                    }
                }
                "oast" => Err("needs an out-of-band callback server: retest it in ProxyMind instead"),
                _ => Err("this kind of proof can't run outside ProxyMind"),
            };
            match test {
                Ok(t) => out.tests.push(t),
                Err(why) => out.skipped.push(skip(why)),
            }
        }
        Ok(out)
    }

    /// The tests as a ZIP: one JSON file per finding, a README and an example
    /// CI workflow. People only; audited.
    pub fn regression_zip(&self, actor: &Actor) -> Result<(Vec<u8>, RegressionExport)> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people export regression tests".into()));
        }
        let export = self.regression_tests()?;
        let mut files: Vec<(String, Vec<u8>)> = export
            .tests
            .iter()
            .map(|t| (format!("tests/finding-{}.json", t.finding.id), serde_json::to_vec_pretty(t).unwrap_or_default()))
            .collect();
        let mut envs: Vec<String> =
            export.tests.iter().flat_map(|t| t.auth.iter().map(|a| regress::auth_env(a))).collect();
        envs.sort();
        envs.dedup();
        let env_lines = if envs.is_empty() {
            "None of these tests need credentials.".to_string()
        } else {
            envs.iter()
                .map(|e| format!("- `{e}`: header lines for that identity, e.g. `Cookie: session=…`"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let skipped = if export.skipped.is_empty() {
            String::new()
        } else {
            let lines: Vec<String> =
                export.skipped.iter().map(|s| format!("- #{} {}: {}", s.finding_id, s.title, s.reason)).collect();
            format!("\n## Findings without a test\n\n{}\n", lines.join("\n"))
        };
        files.push((
            "README.md".into(),
            format!(
                "# ProxyMind regression tests\n\nOne test per proven finding. Run them against a test environment:\n\n\
                 ```\nproxymind regress run tests/ --target https://staging.example.com --junit results.xml\n```\n\n\
                 A test fails while the finding is still there and passes once it is fixed (the exit code is 1 if any \
                 finding is still there). The runner sends requests only to the target (or the origin in each test), \
                 needs no ProxyMind project, and reads credentials from the environment:\n\n{env_lines}\n\n\
                 Only run these against systems you are allowed to test.\n{skipped}"
            )
            .into_bytes(),
        ));
        let secrets: String = envs.iter().map(|e| format!("          {e}: ${{{{ secrets.{e} }}}}\n")).collect();
        let version = concat!("v", env!("CARGO_PKG_VERSION"));
        let workflow = format!(
            "# Copy to .github/workflows/security-regressions.yml, and the tests to security-tests/.\n\
             # Set the STAGING_URL variable and the PM_AUTH_* secrets in the repository settings.\n\
             name: security regressions\n\
             on: [push]\n\
             jobs:\n\
             \x20 proxymind:\n\
             \x20   runs-on: ubuntu-latest\n\
             \x20   env:\n\
             \x20     PROXYMIND_VERSION: {version}\n\
             \x20   steps:\n\
             \x20     - uses: actions/checkout@v4\n\
             \x20     - name: Install ProxyMind\n\
             \x20       run: |\n\
             \x20         name=proxymind-$PROXYMIND_VERSION-x86_64-unknown-linux-gnu\n\
             \x20         curl -sSL https://github.com/ommirkute/ProxyMind/releases/download/$PROXYMIND_VERSION/$name.tar.gz | tar xz\n\
             \x20         mv $name/proxymind .\n\
             \x20     - name: Run the security regression tests\n\
             \x20       env:\n\
             {secrets}\
             \x20         STAGING_URL: ${{{{ vars.STAGING_URL }}}}\n\
             \x20       run: ./proxymind regress run security-tests/tests --target \"$STAGING_URL\" --junit results.xml\n"
        );
        files.push(("github-workflow.yml".into(), workflow.into_bytes()));
        let bytes = pm_tools::zip::write(&files).map_err(ServiceError::Invalid)?;
        self.audit(
            &actor.id(),
            "regression_export",
            json!({ "tests": export.tests.len(), "skipped": export.skipped.len() }),
            "ok",
        )?;
        Ok((bytes, export))
    }
}

/// Runs one test against `target` (`scheme://host[:port]`, default: the
/// test's origin), reading credentials from `env`.
pub async fn run_regression(
    t: &RegressionTest,
    target: Option<&str>,
    verify_tls: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> RegressionResult {
    let started = std::time::Instant::now();
    let r = RegressionResult {
        finding_id: t.finding.id,
        title: t.finding.title.clone(),
        outcome: "error".into(),
        detail: String::new(),
        elapsed_ms: 0,
    };
    let done = |mut r: RegressionResult, outcome: &str, detail: String| {
        r.outcome = outcome.into();
        r.detail = detail;
        r.elapsed_ms = started.elapsed().as_millis() as u64;
        r
    };
    if t.format != FORMAT {
        return done(r, "error", format!("unknown format {:?}", t.format));
    }
    let Some(base) = url::Url::parse(target.unwrap_or(&t.origin)).ok() else {
        return done(r, "error", "bad target URL".into());
    };
    let (Some(host), Some(port)) = (base.host_str(), base.port_or_known_default()) else {
        return done(r, "error", "the target has no host".into());
    };
    let host = host.trim_matches(['[', ']']).to_string();
    let authority = pm_core::authority(base.scheme(), &host, port);
    let ep = pm_replay::Endpoint::new(base.scheme(), &host, port);
    let sender = match pm_replay::Sender::new(verify_tls) {
        Ok(s) => s.with_timeouts(Duration::from_secs(15), Duration::from_secs(60)),
        Err(e) => return done(r, "error", format!("{e:#}")),
    };
    let send = |raw: String| {
        let sender = &sender;
        let ep = &ep;
        async move {
            let method = raw.split(' ').next().unwrap_or("GET").to_string();
            let resp = sender.send(ep, raw.as_bytes(), &method, None).await.map_err(|e| format!("{e:#}"))?;
            let body = pm_http::split_message(&resp.raw).1;
            let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
            Ok::<_, String>((
                resp.head.status,
                String::from_utf8_lossy(&body).into_owned(),
                resp.elapsed.as_millis() as u64,
            ))
        }
    };
    match t.oracle.as_str() {
        "timing" => {
            let Some(baseline) = &t.baseline else { return done(r, "error", "the test has no baseline".into()) };
            let min = t.vulnerable_if.slower_by_ms.unwrap_or(500.0);
            let (mut b, mut p) = (Vec::new(), Vec::new());
            for _ in 0..t.samples.clamp(1, 15) {
                for (tpl, out) in [(baseline, &mut b), (&t.request, &mut p)] {
                    let raw = match regress::fill(tpl, &authority, None, env) {
                        Ok(x) => x,
                        Err(e) => return done(r, "skipped", e),
                    };
                    match send(raw).await {
                        Ok((_, _, ms)) => out.push(ms),
                        Err(e) => return done(r, "error", e),
                    }
                }
            }
            let slow = regress::still_slow(&b, &p, min);
            let detail = format!("baseline {b:?} ms, with the delay payload {p:?} ms (needs {min} ms slower)");
            done(r, if slow { "vulnerable" } else { "fixed" }, detail)
        }
        _ => {
            let token = format!("pmr{:x}", rand_u64());
            let payload = format!("<img src=x onerror=pmRegression('{token}')>");
            let raw = match regress::fill(&t.request, &authority, Some((&payload, &token)), env) {
                Ok(x) => x,
                Err(e) => return done(r, "skipped", e),
            };
            match send(raw).await {
                Err(e) => done(r, "error", e),
                Ok((status, body, _)) => {
                    let vuln = regress::still_vulnerable(&t.vulnerable_if, status, &body, Some(&payload));
                    let why = match (vuln, t.oracle.as_str()) {
                        (true, "reflection") => format!("{status}: the payload still comes back unencoded"),
                        (true, _) => format!("{status}: the response still shows what the proof showed"),
                        (false, _) => format!("{status}: no longer shows the finding"),
                    };
                    done(r, if vuln { "vulnerable" } else { "fixed" }, why)
                }
            }
        }
    }
}

fn rand_u64() -> u64 {
    let t = pm_oast::new_token();
    u64::from_str_radix(&t[..t.len().min(15)], 16).unwrap_or(0x5eed)
}

/// JUnit XML for CI dashboards: a failed test case per finding still there.
pub fn junit(results: &[RegressionResult]) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let failures = results.iter().filter(|r| r.outcome == "vulnerable").count();
    let errors = results.iter().filter(|r| r.outcome == "error").count();
    let skipped = results.iter().filter(|r| r.outcome == "skipped").count();
    let mut x = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"proxymind-regressions\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\">\n",
        results.len()
    );
    for r in results {
        x.push_str(&format!(
            "  <testcase classname=\"proxymind\" name=\"finding #{} {}\" time=\"{:.3}\">",
            r.finding_id,
            esc(&r.title),
            r.elapsed_ms as f64 / 1000.0
        ));
        match r.outcome.as_str() {
            "vulnerable" => x.push_str(&format!("<failure message=\"still vulnerable\">{}</failure>", esc(&r.detail))),
            "error" => x.push_str(&format!("<error message=\"{}\"/>", esc(&r.detail))),
            "skipped" => x.push_str(&format!("<skipped message=\"{}\"/>", esc(&r.detail))),
            _ => {}
        }
        x.push_str("</testcase>\n");
    }
    x.push_str("</testsuite>\n");
    x
}
