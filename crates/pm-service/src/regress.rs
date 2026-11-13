//! Proven findings as regression tests a developer's CI runs: see
//! `pm_tools::regress` for the format. Export builds a test per proven
//! finding (differential authorization, reflection, timing, error-based and
//! boolean SQL injection, path traversal, open redirect and header
//! injection); the runner sends them to the origin they came from or a
//! `--target`, with credentials from the environment, and says which
//! findings are still there. The runner needs no project and sends only to
//! that one origin. Test files never hold credentials, and a run that can't
//! tell (credentials not accepted, the server failing) is an error, never
//! "fixed".

use std::time::Duration;

use pm_policy::{Actor, ActorKind};
use pm_tools::regress::{self, RegressionTest, TestFinding, VulnerableIf};
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

/// The header names that can carry credentials: the usual ones, plus the
/// ones this identity uses.
fn credential_headers(identity: Option<&pm_identity::Identity>) -> Vec<String> {
    let mut names: Vec<String> = pm_identity::AUTH_HEADERS.iter().map(|h| h.to_string()).collect();
    names.extend(identity.iter().flat_map(|i| i.auth.headers.iter().map(|(h, _)| h.to_ascii_lowercase())));
    names.sort();
    names.dedup();
    names
}

/// The environment variable name for credentials no saved identity owns.
const SESSION: &str = "session";

impl Service {
    /// The saved identity whose credentials a request carries, if any.
    fn identity_carrying(&self, carried: &pm_identity::AuthMaterial) -> Option<pm_identity::Identity> {
        let same =
            |a: &(String, String), b: &(String, String)| a.1.len() >= 8 && a.0.eq_ignore_ascii_case(&b.0) && a.1 == b.1;
        let rows = self.store.lock().list_identities().ok()?;
        rows.iter().filter_map(|r| serde_json::from_str::<pm_identity::Identity>(&r.data).ok()).find(|i| {
            i.auth.cookies.iter().any(|c| carried.cookies.iter().any(|x| same(c, x)))
                || i.auth.headers.iter().any(|h| carried.headers.iter().any(|x| same(h, x)))
        })
    }

    /// A request as it goes into a test file: without credentials. Whoever's
    /// they are (the named identity's, or the session the request was
    /// recorded with) becomes an `{{auth:NAME}}` line filled from the
    /// environment at run time. Credentials never go in the file.
    fn portable(&self, raw: &str, identity: Option<&str>) -> (String, Vec<String>) {
        match identity.filter(|i| !i.is_empty()) {
            // Sent without credentials: the test sends it the same way.
            Some(pm_identity::ANONYMOUS) => {
                let bare = pm_identity::apply(raw.as_bytes(), &pm_identity::AuthMaterial::default());
                (String::from_utf8_lossy(&bare).into_owned(), vec![])
            }
            Some(name) => {
                let id = self.load_identity(name).ok();
                (regress::strip_auth(raw, &credential_headers(id.as_ref()), name), vec![name.to_string()])
            }
            None => {
                let carried = pm_identity::auth_from_request(raw.as_bytes());
                if carried.is_empty() {
                    return (raw.to_string(), vec![]);
                }
                let owner = self.identity_carrying(&carried);
                let name = owner.as_ref().map_or(SESSION.to_string(), |i| i.name.clone());
                (regress::strip_auth(raw, &credential_headers(owner.as_ref()), &name), vec![name])
            }
        }
    }

    /// What lets a test tell "fixed" from "the credentials stopped working":
    /// the identity's health check (when it is for this origin) and how the
    /// app looks when logged out.
    fn with_auth_checks(&self, mut t: RegressionTest) -> RegressionTest {
        let Some(id) = t.auth.first().and_then(|name| self.load_identity(name).ok()) else { return t };
        t.logged_out = id.logged_out.as_ref().map(|l| regress::LoggedOutLook {
            statuses: l.statuses.clone(),
            location_contains: l.location_contains.clone(),
            body_contains: l.body_contains.clone(),
        });
        t.auth_check =
            id.health.as_ref().filter(|h| origin_of(&h.url).as_deref() == Some(t.origin.as_str())).map(|h| {
                regress::AuthCheck {
                    request: regress::strip_auth(&h.request, &credential_headers(Some(&id)), &id.name),
                    expect_status: h.expect_status,
                    expect_contains: h.expect_contains.clone(),
                }
            });
        t
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
            // Where a proof made from request templates was sent.
            let template_origin = || {
                exchange(inputs["exchange_id"].as_i64())
                    .map(|x| x.1)
                    .or_else(|| inputs["url"].as_str().and_then(origin_of))
            };
            let oracle = p["oracle"].as_str().unwrap_or_default();
            let test = match oracle {
                "differential_authz" => {
                    let attacker = d["attacker"].as_str().unwrap_or_default();
                    match exchange(d["exchanges"]["attacker"].as_i64()) {
                        None => Err("the attacker's exchange is no longer in the project"),
                        Some((raw, origin)) => {
                            let (request, auth) = self.portable(&raw, Some(attacker));
                            let markers: Vec<String> = d["markers_found"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect();
                            Ok(RegressionTest {
                                auth,
                                vulnerable_if: VulnerableIf {
                                    status_min: Some(200),
                                    status_max: Some(299),
                                    body_contains_any: markers,
                                    ..Default::default()
                                },
                                ..RegressionTest::new(finding, origin, oracle, request)
                            })
                        }
                    }
                }
                "reflection" => match (inputs["raw"].as_str(), d["url"].as_str().and_then(origin_of)) {
                    (Some(raw), Some(origin)) => {
                        let (request, auth) = self.portable(raw, identity);
                        Ok(RegressionTest {
                            auth,
                            vulnerable_if: VulnerableIf { reflects_payload: true, ..Default::default() },
                            ..RegressionTest::new(finding, origin, oracle, request)
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
                            let (request, auth) = self.portable(payload, identity);
                            let (baseline, _) = self.portable(&baseline, identity);
                            Ok(RegressionTest {
                                baseline: Some(baseline),
                                auth,
                                vulnerable_if: VulnerableIf {
                                    slower_by_ms: Some(inputs["min_effect_ms"].as_f64().unwrap_or(500.0)),
                                    ..Default::default()
                                },
                                samples: 5,
                                ..RegressionTest::new(finding, origin, oracle, request)
                            })
                        }
                        _ => Err("the proof's requests are missing"),
                    }
                }
                // Proofs that send a fixed set of requests: the test re-sends
                // them and judges the answers the way the proof did.
                "sql_error" | "boolean_injection" | "path_traversal" => {
                    let raws: Vec<&str> =
                        inputs["raws"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                    let markers: Vec<String> = inputs["markers"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                    // The request that carries the payload, and whether the set is whole.
                    let (shown, whole) = match oracle {
                        "sql_error" => (1, raws.len() == 4),
                        "boolean_injection" => (1, raws.len() == 3),
                        _ => (2, raws.len() >= 3 && markers.len() == raws.len() - 2),
                    };
                    match template_origin().filter(|_| whole) {
                        None => Err("the proof's requests are missing"),
                        Some(origin) => {
                            let made: Vec<(String, Vec<String>)> =
                                raws.iter().map(|r| self.portable(r, identity)).collect();
                            let auth = made.iter().find(|m| !m.1.is_empty()).map(|m| m.1.clone()).unwrap_or_default();
                            let requests: Vec<String> = made.into_iter().map(|m| m.0).collect();
                            let payload_request = requests[shown].clone();
                            Ok(RegressionTest {
                                format: regress::FORMAT_2.into(),
                                requests,
                                markers,
                                auth,
                                ..RegressionTest::new(finding, origin, oracle, payload_request)
                            })
                        }
                    }
                }
                "marker" => match (inputs["raw"].as_str(), inputs["marker_kind"].as_str(), template_origin()) {
                    (Some(raw), Some(kind), Some(origin)) => {
                        let (request, auth) = self.portable(raw, identity);
                        Ok(RegressionTest {
                            format: regress::FORMAT_2.into(),
                            marker_kind: Some(kind.to_string()),
                            auth,
                            ..RegressionTest::new(finding, origin, oracle, request)
                        })
                    }
                    _ => Err("the proof's request template is missing"),
                },
                "oast" => Err("needs an out-of-band callback server: retest it in ProxyMind instead"),
                _ => Err("this kind of proof can't run outside ProxyMind"),
            };
            match test {
                Ok(t) => out.tests.push(self.with_auth_checks(t)),
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
                 A test fails while the finding is still there and passes once it is fixed. A test that can't tell is \
                 an error, not a pass: the credentials were not accepted (an expired token), or the server failed. The \
                 exit code is 1 if any finding is still there or any test had an error. The runner sends requests only \
                 to the target (or the origin in each test), needs no ProxyMind project, and reads credentials from \
                 the environment:\n\n{env_lines}\n\n\
                 The test files hold no credentials: each `{{{{auth:NAME}}}}` line is filled from `PM_AUTH_<NAME>` \
                 when the test runs. If the page a test requests needs no login, delete that line from the test.\n\n\
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

/// One answer from the target.
struct Reply {
    status: u16,
    location: Option<String>,
    /// De-chunked, decompressed.
    body: String,
    raw: Vec<u8>,
    ms: u64,
}

/// What a test's answers say.
enum Judged {
    Vulnerable(String),
    Fixed(String),
    /// The run can't say (outcome, why): never reported as fixed.
    Stop(&'static str, String),
}

/// Runs one test against `target` (`scheme://host[:port]`, default: the
/// test's origin), reading credentials from `env`. A test is `fixed` only
/// when the answers show it: credentials that are not accepted, or a server
/// that fails, are an `error`.
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
    if !regress::supported(&t.format) {
        return done(r, "error", format!("unknown format {:?}: this test needs a newer ProxyMind", t.format));
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
            Ok::<_, String>(Reply {
                status: resp.head.status,
                location: pm_http::header(&resp.head.headers, "location")
                    .map(|l| String::from_utf8_lossy(l).into_owned()),
                body: crate::proof::body_text(&resp.raw),
                ms: resp.elapsed.as_millis() as u64,
                raw: resp.raw,
            })
        }
    };
    let envs = t.auth.iter().map(|a| regress::auth_env(a)).collect::<Vec<_>>().join(", ");
    // Why an answer can't show whether the finding is fixed, if it can't:
    // the credentials were not accepted, or (`must_work`: a request that has
    // no reason to fail) the server failed.
    let cant_tell = |reply: &Reply, must_work: bool| -> Option<String> {
        let rejected = !t.auth.is_empty()
            && regress::credentials_rejected(
                reply.status,
                reply.location.as_deref(),
                &reply.body,
                t.logged_out.as_ref(),
            );
        if rejected {
            return Some(format!(
                "{}: the credentials in {envs} were not accepted (expired?), so this can't tell whether the finding is fixed",
                reply.status
            ));
        }
        (must_work && reply.status >= 500)
            .then(|| format!("{}: the server failed, so this can't tell whether the finding is fixed", reply.status))
    };
    // Sends each template in turn. `Err` is the outcome to report.
    let send_all = |templates: Vec<String>| {
        let (send, authority) = (&send, &authority);
        async move {
            let mut replies = Vec::new();
            for tpl in templates {
                let raw = regress::fill(&tpl, authority, None, env).map_err(|e| ("skipped", e))?;
                replies.push(send(raw).await.map_err(|e| ("error", e))?);
            }
            Ok::<_, (&'static str, String)>(replies)
        }
    };
    let reason = |v: &pm_proof::Verdict| v.reasons.last().cloned().unwrap_or_default();

    let judged = match t.oracle.as_str() {
        "timing" => 'timing: {
            let Some(baseline) = &t.baseline else {
                break 'timing Judged::Stop("error", "the test has no baseline".into());
            };
            let min = t.vulnerable_if.slower_by_ms.unwrap_or(500.0);
            let (mut b, mut p) = (Vec::new(), Vec::new());
            for _ in 0..t.samples.clamp(1, 15) {
                match send_all(vec![baseline.clone(), t.request.clone()]).await {
                    Ok(mut pair) => {
                        p.extend(pair.pop());
                        b.extend(pair.pop());
                    }
                    Err((outcome, why)) => break 'timing Judged::Stop(outcome, why),
                }
            }
            let ms = |x: &[Reply]| x.iter().map(|r| r.ms).collect::<Vec<u64>>();
            let detail =
                format!("baseline {:?} ms, with the delay payload {:?} ms (needs {min} ms slower)", ms(&b), ms(&p));
            if regress::still_slow(&ms(&b), &ms(&p), min) {
                Judged::Vulnerable(detail)
            } else if let Some(why) =
                b.iter().find_map(|x| cant_tell(x, true)).or_else(|| p.iter().find_map(|x| cant_tell(x, false)))
            {
                Judged::Stop("error", why)
            } else {
                Judged::Fixed(detail)
            }
        }
        // The proof's own requests, judged the way the proof judged them.
        "sql_error" | "boolean_injection" | "path_traversal" => 'multi: {
            let n = t.requests.len();
            let whole = match t.oracle.as_str() {
                "sql_error" => n == 4,
                "boolean_injection" => n == 3,
                _ => n >= 3 && t.markers.len() == n - 2,
            };
            if !whole {
                break 'multi Judged::Stop("error", "the test's requests are missing".into());
            }
            // The true/false split has to repeat, as in the proof.
            let rounds = if t.oracle == "boolean_injection" { 2 } else { 1 };
            let mut replies: Vec<Vec<Reply>> = Vec::new();
            for _ in 0..rounds {
                match send_all(t.requests.clone()).await {
                    Ok(x) => replies.push(x),
                    Err((outcome, why)) => break 'multi Judged::Stop(outcome, why),
                }
            }
            let raws = |round: &[Reply]| round.iter().map(|x| x.raw.clone()).collect::<Vec<Vec<u8>>>();
            let (verdict, _) = match t.oracle.as_str() {
                "sql_error" => crate::proof::judge_sql_error(&raws(&replies[0])),
                "boolean_injection" => {
                    let rounds: Vec<[Vec<u8>; 3]> =
                        replies.iter().map(|x| [x[0].raw.clone(), x[1].raw.clone(), x[2].raw.clone()]).collect();
                    crate::proof::judge_boolean(&rounds)
                }
                _ => crate::proof::judge_traversal(&t.requests, &t.markers, &raws(&replies[0])),
            };
            let first = &replies[0];
            if verdict.proven {
                Judged::Vulnerable(reason(&verdict))
            } else if let Some(why) =
                cant_tell(&first[0], true).or_else(|| first.iter().skip(1).find_map(|x| cant_tell(x, false)))
            {
                Judged::Stop("error", why)
            } else {
                Judged::Fixed(verdict.reasons.first().cloned().unwrap_or_default())
            }
        }
        "marker" => 'marker: {
            let marker = match crate::proof::marker_token() {
                Ok(m) => m,
                Err(e) => break 'marker Judged::Stop("error", e.to_string()),
            };
            let kind = t.marker_kind.as_deref().unwrap_or_default();
            if !crate::proof::MARKER_KINDS.contains(&kind) || !t.request.contains("{{marker}}") {
                break 'marker Judged::Stop("error", "the test has no {{marker}} or an unknown marker_kind".into());
            }
            match send_all(vec![t.request.replace("{{marker}}", &marker)]).await {
                Err((outcome, why)) => Judged::Stop(outcome, why),
                Ok(replies) => {
                    let (verdict, _) = crate::proof::judge_marker(kind, &marker, &replies[0].raw, &host);
                    if verdict.proven {
                        Judged::Vulnerable(reason(&verdict))
                    } else if let Some(why) = cant_tell(&replies[0], true) {
                        Judged::Stop("error", why)
                    } else {
                        Judged::Fixed(reason(&verdict))
                    }
                }
            }
        }
        "differential_authz" | "reflection" => {
            let token = format!("pmr{:x}", rand_u64());
            let payload = format!("<img src=x onerror=pmRegression('{token}')>");
            match regress::fill(&t.request, &authority, Some((&payload, &token)), env) {
                Err(e) => Judged::Stop("skipped", e),
                Ok(raw) => match send(raw).await {
                    Err(e) => Judged::Stop("error", e),
                    Ok(reply) => {
                        let status = reply.status;
                        if regress::still_vulnerable(&t.vulnerable_if, status, &reply.body, Some(&payload)) {
                            Judged::Vulnerable(if t.oracle == "reflection" {
                                format!("{status}: the payload still comes back unencoded")
                            } else {
                                format!("{status}: the response still shows what the proof showed")
                            })
                        } else if let Some(why) = cant_tell(&reply, true) {
                            Judged::Stop("error", why)
                        } else {
                            Judged::Fixed(format!("{status}: no longer shows the finding"))
                        }
                    }
                },
            }
        }
        other => Judged::Stop("error", format!("unknown kind of test {other:?}: this test needs a newer ProxyMind")),
    };
    match judged {
        Judged::Vulnerable(detail) => done(r, "vulnerable", detail),
        Judged::Stop(outcome, detail) => done(r, outcome, detail),
        Judged::Fixed(detail) => {
            // Apps that answer an expired session with 403 or an ordinary page
            // look fixed: ask for something these credentials may do.
            if let (false, Some(check)) = (t.auth.is_empty(), &t.auth_check) {
                match send_all(vec![check.request.clone()]).await {
                    Err((outcome, why)) => return done(r, outcome, why),
                    Ok(replies) if !check.passes(replies[0].status, &replies[0].body) => {
                        let why = format!(
                            "the credentials in {envs} no longer work ({} on the check request), so this can't tell \
                             whether the finding is fixed",
                            replies[0].status
                        );
                        return done(r, "error", why);
                    }
                    Ok(_) => {}
                }
            }
            done(r, "fixed", detail)
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
