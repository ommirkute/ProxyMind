//! `proxymind ci`: one unattended run for a pipeline. It checks the target against the rules of engagement, logs in
//! the identities it was given, imports an API description, crawls, scans with a profile, proves what it can, and
//! turns the findings into a [`CiSummary`] (plus SARIF) compared with a baseline.
//!
//! The run acts as `ci:<name>`. Nobody is there to approve, so whatever the rules leave at `approve` is skipped and
//! reported, never granted; the `ci` kind has its own `tiers.ci` section in the ROE and its defaults refuse
//! everything above active-safe (see `pm_policy::roe::default_decision`).
//!
//! A project file is active content (threat model F-2). This module never starts listeners, schedules or workflow
//! triggers (those belong to `proxymind ui` and the desktop app), and while it runs the service ignores what a
//! project file could use to steer it: saved network settings (upstream proxies, host overrides), session rules and
//! macros, and OAST settings; identity logins run as the CI actor, not as whoever saved the identity.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pm_identity::Identity;
use pm_policy::{Actor, ActorKind, Decision, Target, Tier};
use pm_tools::ci::{self, Baseline, CiCheck, CiFinding, CiProof, CiSummary, Gate, PROVEN_STATUSES, SUMMARY_FORMAT};
use serde_json::Value;

use crate::{
    Authorization, CrawlRequest, CrawlResult, OpenApiImportRequest, OpenApiImportResult, ReportOptions, Result,
    ScanTaskRequest, ScanTaskStatus, ScanTaskView, Service, ServiceError, now_ms,
};

/// Request and time caps of a run, and what a project file may not steer. One per service.
#[derive(Default)]
pub(crate) struct RunGuard {
    /// Ignore settings a project file could use to steer a run (see the module documentation).
    pub isolated: bool,
    /// Logins run as this actor instead of the identity's creator.
    pub login_actor: Option<Actor>,
    max_requests: Option<u64>,
    deadline: Option<Instant>,
    budget_minutes: Option<u64>,
    /// Requests sent to a target since the guard was set.
    sent: u64,
    /// Why a send was refused: set once, and sticks.
    exhausted: Option<String>,
}

impl RunGuard {
    fn limit_reason(&self) -> Option<String> {
        if let Some(why) = &self.exhausted {
            return Some(why.clone());
        }
        if let Some(d) = self.deadline
            && Instant::now() >= d
        {
            return Some(format!("the time budget ({} minute(s)) is spent", self.budget_minutes.unwrap_or_default()));
        }
        if let Some(m) = self.max_requests
            && self.sent >= m
        {
            return Some(format!("the request budget ({m} requests) is spent"));
        }
        None
    }
}

impl Service {
    /// Counts one request against the run's caps. Called right before every send; refused once a cap is reached
    /// (and the refusal sticks, so callers that swallow errors still leave the run marked as cut short).
    pub(crate) fn spend_request(&self) -> std::result::Result<(), String> {
        let mut g = self.run_guard.lock();
        if let Some(why) = g.limit_reason() {
            g.exhausted.get_or_insert_with(|| why.clone());
            return Err(why);
        }
        g.sent += 1;
        Ok(())
    }

    /// A project setting, or nothing during a CI run or in safe mode (a project file must not point probes at a
    /// callback server).
    pub(crate) fn setting_unless_isolated(&self, key: &str) -> Result<Option<String>> {
        if self.run_guard.lock().isolated || self.safe_mode() {
            return Ok(None);
        }
        Ok(self.store.read(|db| db.get_setting(key))?)
    }

    /// Why the run can send no more, if it can't.
    fn budget_spent(&self) -> Option<String> {
        self.run_guard.lock().limit_reason()
    }

    /// Set only when a send was actually refused.
    fn budget_refused(&self) -> Option<String> {
        self.run_guard.lock().exhausted.clone()
    }

    fn requests_sent(&self) -> u64 {
        self.run_guard.lock().sent
    }

    /// Starts a run's guard: isolation, the login actor and the caps.
    fn ci_begin(&self, actor: &Actor, opts: &CiOptions) {
        {
            let mut g = self.run_guard.lock();
            *g = RunGuard {
                isolated: true,
                login_actor: Some(actor.clone()),
                max_requests: opts.max_requests,
                deadline: opts.budget_minutes.map(|m| Instant::now() + Duration::from_secs(m.saturating_mul(60))),
                budget_minutes: opts.budget_minutes,
                sent: 0,
                exhausted: None,
            };
        }
        // Saved upstream proxies, host overrides and client certificates came from the project file: not for CI.
        if let Err(e) = self.sender.network().set(pm_replay::NetConfig::default()) {
            tracing::warn!("network settings not reset for the CI run: {e:#}");
        }
    }
}

/// What to run and how to judge it.
pub struct CiOptions {
    /// The URL to test (already checked to exist, not yet to be in scope).
    pub target: String,
    /// A scan profile: light, default, thorough, api-only, or one saved in the project.
    pub profile: String,
    /// The name part of the `ci:<name>` actor.
    pub actor_name: String,
    pub max_requests: Option<u64>,
    pub budget_minutes: Option<u64>,
    /// Identity definitions to load into the project for this run (credentials already filled in).
    pub identity_defs: Vec<Identity>,
    /// Identities to log in and use, the first one scans; empty means the ones in `identity_defs`.
    pub use_identities: Vec<String>,
    /// Values that must never appear in output (credentials from the environment).
    pub secrets: Vec<String>,
    /// An OpenAPI or Swagger description (text) to import and send the GET examples of.
    pub openapi: Option<String>,
    /// Crawl in a headless browser when Chromium is installed (otherwise links and forms only).
    pub browser: bool,
    /// The baseline to compare with, and the name to show for it.
    pub baseline: Option<(String, Baseline)>,
    pub gate: Gate,
    /// Accept a run where the rules of engagement skipped some checks (or nothing was found to scan).
    pub allow_skipped: bool,
    /// Whether the sender verifies the target's TLS certificate (set by whoever built the service).
    pub tls_verified: bool,
    /// `ProxyMind x.y.z`.
    pub tool: String,
}

/// The result of a run: the summary and the SARIF file's contents.
pub struct CiRun {
    pub summary: CiSummary,
    pub sarif: Value,
}

/// What the scan task's notes say the rules refused.
fn policy_skips(view: &ScanTaskView) -> Vec<String> {
    let ops = |what: &str| -> Vec<&str> {
        view.notes
            .iter()
            .filter(|n| n.contains(what))
            .map(|n| n.find(": needs approval").or_else(|| n.find(": denied (")).map_or(n.as_str(), |i| &n[..i]))
            .collect()
    };
    let mut out = Vec::new();
    let approval = ops("needs approval");
    if !approval.is_empty() {
        out.push(format!(
            "{} operation(s) not scanned: the rules of engagement leave them at \"approve\" for CI, which nobody can \
             grant here (first: {})",
            approval.len(),
            ci::clean(approval[0], 80)
        ));
    }
    let denied = ops(": denied (");
    if !denied.is_empty() {
        out.push(format!(
            "{} operation(s) not scanned: the rules of engagement refuse them for CI (first: {})",
            denied.len(),
            ci::clean(denied[0], 80)
        ));
    }
    out
}

impl Service {
    /// Runs the whole job. `Err` means it could not start (a target outside the scope, an unknown profile, unreadable
    /// input); everything that goes wrong later is a reason in the summary's `incomplete`, so the files are still
    /// written and the exit code says "not clean".
    pub async fn ci_run(self: &Arc<Self>, opts: &CiOptions, progress: &(dyn Fn(&str) + Send + Sync)) -> Result<CiRun> {
        let started = Instant::now();
        let started_at = jiff::Timestamp::now().to_string();
        let started_ms = now_ms();
        let actor =
            Actor::parse(&format!("ci:{}", opts.actor_name)).map_err(|e| ServiceError::Invalid(e.to_string()))?;

        // The target must be in scope, or nothing happens.
        let endpoint = crate::replay::parse_url_endpoint(&opts.target)?;
        let url = url::Url::parse(&opts.target).map_err(|e| ServiceError::Invalid(format!("bad target URL: {e}")))?;
        let in_scope = Target::from_parts(&endpoint.scheme, &endpoint.host, endpoint.port, url.path())
            .map_err(|e| ServiceError::Invalid(e.to_string()))
            .and_then(|t| {
                self.policy.scope_check(&t).map_err(|why| {
                    ServiceError::Invalid(format!(
                        "the target {} is not allowed by the rules of engagement: {why}",
                        ci::clean(&opts.target, 200)
                    ))
                })
            });
        in_scope?;
        // An unknown profile is an error before anything is sent.
        let profile = self.scan_profile(&opts.profile)?;
        self.ci_begin(&actor, opts);

        let secrets: Vec<String> = opts.secrets.iter().filter(|s| s.len() >= 3).cloned().collect();
        let scrub = |s: &str| -> String {
            let mut t = self.redactor_of(&actor).redact(s);
            for secret in &secrets {
                t = t.replace(secret.as_str(), "[redacted]");
            }
            ci::clean(&t, 400)
        };

        let mut incomplete: Vec<String> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        let mut checks: Vec<CiCheck> = Vec::new();
        let roe = self.policy.roe();
        let decision = |t: Tier| roe.tier_decision(ActorKind::Ci, t);
        if decision(Tier::ActiveIntrusive) != Decision::Allow {
            skipped.push(format!(
                "tiers.ci.active_intrusive is \"{}\" in the rules of engagement, so scan probes are not sent; set it \
                 to allow to scan",
                decision(Tier::ActiveIntrusive).as_str()
            ));
        }

        // 1. The target answers.
        progress(&format!("checking that {} answers", ci::clean(&opts.target, 200)));
        let reachable = self.ci_probe(&actor, &endpoint, &url, opts.tls_verified).await;
        match &reachable {
            Ok(()) => checks.push(CiCheck::new("target reachable", "passed", "")),
            Err(why) => {
                let why = scrub(why);
                match self.budget_refused() {
                    Some(b) => incomplete.push(format!("stopped before the scan finished: {b}")),
                    None => incomplete.push(format!("the target is not reachable: {why}")),
                }
                checks.push(CiCheck::new("target reachable", "error", why));
            }
        }

        let steps_ok = reachable.is_ok();
        // 2. Identities.
        let mut identity_names: Vec<String> = Vec::new();
        if steps_ok {
            identity_names = self.ci_identities(&actor, opts, &mut checks, &mut incomplete, &scrub, progress).await;
        }
        let scan_identity = identity_names.first().cloned();

        // 3. An API description.
        if steps_ok
            && incomplete.is_empty()
            && let Some(spec) = &opts.openapi
        {
            progress("importing the API description");
            self.ci_openapi(
                &actor,
                opts,
                spec,
                scan_identity.clone(),
                &mut checks,
                &mut incomplete,
                &mut skipped,
                &scrub,
            )
            .await;
        }

        // 4. Content discovery (not in the light profile).
        let go = |incomplete: &Vec<String>| steps_ok && incomplete.is_empty() && self.budget_spent().is_none();
        if go(&incomplete) && profile.name != "light" {
            progress("looking for exposed files and an API description");
            match self.auto_discover(&actor).await {
                Ok(d) => {
                    for s in d.skipped.iter().take(5) {
                        skipped.push(format!("content discovery: {}", scrub(s)));
                    }
                    checks.push(CiCheck::new(
                        "content discovery",
                        "passed",
                        format!("{} path(s) found, {} exposure lead(s)", d.found, d.leads.len()),
                    ));
                }
                Err(e) => {
                    incomplete.push(format!("content discovery failed: {}", scrub(&e.to_string())));
                    checks.push(CiCheck::new("content discovery", "error", scrub(&e.to_string())));
                }
            }
        }

        // 5. Crawl and scan.
        if go(&incomplete) {
            progress(&format!("crawling and scanning with the {} profile", profile.name));
            self.ci_scan(
                &actor,
                opts,
                &profile,
                scan_identity.clone(),
                &mut checks,
                &mut incomplete,
                &mut skipped,
                &scrub,
                progress,
            )
            .await;
        } else if steps_ok {
            checks.push(CiCheck::new("crawl and scan", "skipped", "an earlier step did not finish"));
            if let Some(why) = self.budget_spent() {
                incomplete.push(format!("stopped before the scan finished: {why}"));
            }
        }

        // 6. More than one identity: what each can reach.
        if go(&incomplete) && identity_names.len() > 1 {
            progress("checking access control between the identities");
            let max_pages = profile.max_pages.unwrap_or(30).min(100);
            for name in identity_names.iter().skip(1) {
                let r = self
                    .crawl(
                        &actor,
                        CrawlRequest {
                            url: opts.target.clone(),
                            max_pages: Some(max_pages),
                            identity: Some(name.clone()),
                            browser: Some(false),
                            ..Default::default()
                        },
                    )
                    .await;
                match r {
                    Ok(CrawlResult::Done { .. }) => {}
                    Ok(_) => skipped.push(format!("crawl as {name}: not allowed for CI by the rules of engagement")),
                    Err(e) => incomplete.push(format!("crawl as {name} failed: {}", scrub(&e.to_string()))),
                }
            }
            let ac = self.auto_access_control(&actor).await;
            let gq = self.graphql_object_access(&actor).await;
            match (ac, gq) {
                (Ok(r), Ok(g)) => checks.push(CiCheck::new(
                    "access control",
                    "passed",
                    format!("{} candidate(s), {} leak(s), {} GraphQL lead(s)", r.candidates, r.leaks, g.len()),
                )),
                (Err(e), _) | (_, Err(e)) => {
                    incomplete.push(format!("the access-control checks failed: {}", scrub(&e.to_string())));
                    checks.push(CiCheck::new("access control", "error", scrub(&e.to_string())));
                }
            }
        }

        // 7. Proving.
        if go(&incomplete) {
            progress("proving what was found");
            match self.auto_prove(&actor).await {
                Ok(p) => {
                    let refused =
                        p.results.iter().filter(|r| r.reasons.iter().any(|x| x.contains("for this actor"))).count();
                    if refused > 0 {
                        skipped.push(format!(
                            "{refused} finding(s) could not be proven: the rules of engagement do not let CI send the \
                             proof requests"
                        ));
                    }
                    checks.push(CiCheck::new(
                        "automatic proving",
                        "passed",
                        format!("{} attempted, {} proven", p.attempted, p.proven),
                    ));
                }
                Err(e) => {
                    incomplete.push(format!("proving failed: {}", scrub(&e.to_string())));
                    checks.push(CiCheck::new("automatic proving", "error", scrub(&e.to_string())));
                }
            }
        } else if steps_ok {
            checks.push(CiCheck::new("automatic proving", "skipped", "an earlier step did not finish"));
            if let Some(why) = self.budget_spent() {
                incomplete.push(format!("stopped before proving finished: {why}"));
            }
        }

        // A cap that stopped a send means the run was cut short, whichever step it hit. (A spent budget with
        // nothing left to do is not an error: only a refused send counts.)
        if let Some(why) = self.budget_refused()
            && !incomplete.iter().any(|i| i.contains("budget"))
        {
            incomplete.push(format!("stopped before the scan finished: {why}"));
        }
        if opts.allow_skipped {
            // Accepted, but still said: the skips stay in `skipped`.
        } else {
            if !skipped.is_empty() {
                incomplete.push(format!(
                    "{} thing(s) skipped by the rules of engagement (listed above); --allow-skipped accepts that",
                    skipped.len()
                ));
            }
        }

        // Findings of this run.
        let mut findings = self.ci_findings(started_ms, &scrub)?;
        findings = ci::dedupe(findings);
        let fixed = ci::classify(&mut findings, opts.baseline.as_ref().map(|b| &b.1), &opts.gate);
        let mut summary = CiSummary {
            format: SUMMARY_FORMAT.into(),
            tool: opts.tool.clone(),
            target: ci::clean(&opts.target, 300),
            profile: opts.profile.clone(),
            actor: actor.id(),
            started_at,
            duration_ms: started.elapsed().as_millis() as u64,
            requests: self.requests_sent(),
            tls_verified: opts.tls_verified,
            fail_on: opts.gate.fail_on,
            min_severity: opts.gate.min_severity.clone(),
            baseline: opts.baseline.as_ref().map(|b| b.0.clone()),
            baseline_written: None,
            complete: true,
            incomplete,
            skipped,
            checks,
            counts: Default::default(),
            findings,
            fixed,
            exit_code: 0,
        };
        summary.finish();

        let sarif = self.ci_sarif(&summary)?;
        self.audit(
            &actor.id(),
            "ci_run",
            serde_json::json!({
                "target": summary.target, "profile": summary.profile, "requests": summary.requests,
                "findings": summary.counts.total, "failing": summary.counts.failing, "complete": summary.complete,
                "exit_code": summary.exit_code,
            }),
            if summary.exit_code == 0 { "ok" } else { "attention" },
        )?;
        Ok(CiRun { summary, sarif })
    }

    /// One GET to the target, through the gate and recorded like any send.
    async fn ci_probe(
        &self,
        actor: &Actor,
        endpoint: &pm_replay::Endpoint,
        url: &url::Url,
        tls_verified: bool,
    ) -> std::result::Result<(), String> {
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let authority = pm_core::authority(&endpoint.scheme, &endpoint.host, endpoint.port);
        let raw = format!(
            "GET {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: ProxyMind-CI\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let out = self.outgoing(actor, endpoint.clone(), raw.as_bytes(), true).map_err(|e| e.to_string())?;
        match self.gate_send(actor, "ci_probe", &out, None, true, None).map_err(|e| e.to_string())? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => {
                return Err(format!("the rules of engagement refuse the request: {}", reasons.join("; ")));
            }
            Authorization::PendingApproval { .. } => {
                return Err("the rules of engagement want an approval, which CI never grants".into());
            }
        }
        let (sent, _) = self.send_as(actor, &out, None, true, "ci").await.map_err(|e| e.to_string())?;
        match sent.status {
            Some(502..=504) => {
                Err(format!("the target answered {} (a gateway error)", sent.status.unwrap_or_default()))
            }
            Some(_) => Ok(()),
            None => {
                let e = sent.error.unwrap_or_else(|| "no answer".into());
                let lower = e.to_ascii_lowercase();
                let hint = if tls_verified
                    && (lower.contains("certificate") || lower.contains("handshake") || lower.contains("tls"))
                {
                    " (the certificate is checked; use --insecure only for a staging host with a self-signed one)"
                } else {
                    ""
                };
                Err(format!("{e}{hint}"))
            }
        }
    }

    /// Loads the identity definitions, logs each identity in and checks its session. Returns the names to use.
    async fn ci_identities(
        &self,
        actor: &Actor,
        opts: &CiOptions,
        checks: &mut Vec<CiCheck>,
        incomplete: &mut Vec<String>,
        scrub: &dyn Fn(&str) -> String,
        progress: &(dyn Fn(&str) + Send + Sync),
    ) -> Vec<String> {
        for ident in &opts.identity_defs {
            if !pm_identity::valid_name(&ident.name) || ident.name == pm_identity::ANONYMOUS {
                incomplete.push(format!("bad identity name {:?}", ci::clean(&ident.name, 40)));
                return Vec::new();
            }
            // Created by the CI actor, so a login recipe in it is gated as CI.
            if let Err(e) = self.save_identity(ident, &actor.id(), "unknown") {
                incomplete.push(format!("could not load identity {}: {}", ident.name, scrub(&e.to_string())));
                return Vec::new();
            }
        }
        let names: Vec<String> = if opts.use_identities.is_empty() {
            opts.identity_defs.iter().map(|i| i.name.clone()).collect()
        } else {
            opts.use_identities.clone()
        };
        let mut usable = Vec::new();
        for name in names {
            progress(&format!("logging in as {name}"));
            let label = format!("login {name}");
            let ident = match self.load_identity(&name) {
                Ok(i) => i,
                Err(_) => {
                    let why = format!(
                        "identity {} is not defined (give it with --identity-file or --project)",
                        ci::clean(&name, 40)
                    );
                    incomplete.push(why.clone());
                    checks.push(CiCheck::new(&label, "error", why));
                    continue;
                }
            };
            let outcome: std::result::Result<String, String> = if ident.health.is_some() {
                match self.identity_check(actor, &name).await {
                    Ok(c) if c.status == "ok" => Ok("session works".into()),
                    Ok(c) => Err(format!("{}: {}", c.status, c.notes.join("; "))),
                    Err(e) => Err(e.to_string()),
                }
            } else if ident.login.is_some() {
                self.identity_login(&name)
                    .await
                    .map(|l| format!("logged in ({})", l.join(", ")))
                    .map_err(|e| e.to_string())
            } else {
                Ok("static credentials, no health check to confirm they work".into())
            };
            match outcome {
                Ok(detail) => {
                    checks.push(CiCheck::new(&label, "passed", scrub(&detail)));
                    usable.push(name);
                }
                Err(why) => {
                    let why = scrub(&why);
                    incomplete.push(format!("login as {} failed: {why}", ci::clean(&name, 40)));
                    checks.push(CiCheck::new(&label, "error", why));
                }
            }
        }
        usable
    }

    #[allow(clippy::too_many_arguments)]
    async fn ci_openapi(
        &self,
        actor: &Actor,
        opts: &CiOptions,
        spec: &str,
        identity: Option<String>,
        checks: &mut Vec<CiCheck>,
        incomplete: &mut Vec<String>,
        skipped: &mut Vec<String>,
        scrub: &dyn Fn(&str) -> String,
    ) {
        let base = opts.target.trim_end_matches('/').to_string();
        let mut req = OpenApiImportRequest {
            spec: Some(spec.to_string()),
            base_url: Some(base),
            send_examples: true,
            identity,
            ..Default::default()
        };
        let mut r = self.openapi_import(actor, req.clone()).await;
        // A description with no GET operations still tells the scanner about its other operations.
        if matches!(&r, Err(e) if e.to_string().contains("no GET operations")) {
            req.send_examples = false;
            r = self.openapi_import(actor, req).await;
        }
        match r {
            Ok(OpenApiImportResult::Imported { operations, sent, skipped: not_sent, .. }) => {
                for s in not_sent.iter().take(3) {
                    skipped.push(format!("API description: {}", scrub(s)));
                }
                checks.push(CiCheck::new(
                    "API description",
                    "passed",
                    format!("{} operation(s), {} GET example(s) sent", operations.len(), sent.len()),
                ));
            }
            Ok(OpenApiImportResult::Denied { reasons }) => {
                let why = scrub(&reasons.join("; "));
                skipped.push(format!("API description examples: {why}"));
                checks.push(CiCheck::new("API description", "skipped", why));
            }
            Ok(OpenApiImportResult::PendingApproval { summary, .. }) => {
                let why = format!("needs approval ({})", scrub(&summary));
                skipped.push(format!("API description examples: {why}"));
                checks.push(CiCheck::new("API description", "skipped", why));
            }
            Err(e) => {
                let why = scrub(&e.to_string());
                incomplete.push(format!("the API description could not be imported: {why}"));
                checks.push(CiCheck::new("API description", "error", why));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn ci_scan(
        self: &Arc<Self>,
        actor: &Actor,
        opts: &CiOptions,
        profile: &crate::ScanProfile,
        identity: Option<String>,
        checks: &mut Vec<CiCheck>,
        incomplete: &mut Vec<String>,
        skipped: &mut Vec<String>,
        scrub: &dyn Fn(&str) -> String,
        progress: &(dyn Fn(&str) + Send + Sync),
    ) {
        let mut req = ScanTaskRequest {
            url: opts.target.clone(),
            identity,
            browser: (!opts.browser).then_some(false),
            ..Default::default()
        };
        profile.apply(&mut req);
        // Smuggling, uploads and races are destructive-tier: with the tier not allowed for CI they would make the
        // gate refuse the whole operation, so they are left out and reported.
        let roe = self.policy.roe();
        if roe.tier_decision(ActorKind::Ci, Tier::Destructive) != Decision::Allow {
            let before = req.checks.len();
            req.checks.retain(|c| !pm_scan::active::APPROVAL_CHECKS.contains(&c.as_str()));
            if req.checks.len() != before {
                skipped.push(
                    "request smuggling, file upload and race checks (this profile asks for them) need the destructive \
                     tier, which the rules of engagement do not allow for CI"
                        .into(),
                );
            }
        }
        let started = match self.scan_task_start(actor, req) {
            Ok(v) => v,
            Err(e) => {
                let why = scrub(&e.to_string());
                incomplete.push(format!("the scan could not start: {why}"));
                checks.push(CiCheck::new("crawl and scan", "error", why));
                return;
            }
        };
        let id = started.task_id;
        let mut last = String::new();
        let view = loop {
            let v = match self.scan_task_status(actor, &id) {
                Ok(v) => v,
                Err(e) => {
                    incomplete.push(format!("lost the scan task: {}", scrub(&e.to_string())));
                    return;
                }
            };
            let line = format!(
                "{:?}: {} pages, {}/{} operations, {} requests",
                v.status, v.pages_crawled, v.targets_done, v.targets_total, v.requests
            );
            if line != last {
                progress(&line);
                last = line;
            }
            if !v.status.running() {
                break v;
            }
            if self.budget_spent().is_some() {
                let _ = self.scan_task_cancel(actor, &id);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        match view.status {
            ScanTaskStatus::Done => {
                let skips = policy_skips(&view);
                skipped.extend(skips.iter().cloned());
                let scanned = view.targets_total.saturating_sub(
                    view.notes.iter().filter(|n| n.contains("needs approval") || n.contains(": denied (")).count(),
                );
                let detail = format!(
                    "{} page(s) crawled, {} operation(s) scanned, {} scan request(s), {} issue(s)",
                    view.pages_crawled,
                    scanned,
                    view.requests,
                    view.issues.len()
                );
                if view.targets_total == 0 {
                    skipped.push(
                        "nothing to scan: the crawl found no operations (pages with parameters or forms)".to_string(),
                    );
                    checks.push(CiCheck::new("crawl and scan", "skipped", "no operations found to scan"));
                } else if scanned == 0 {
                    checks.push(CiCheck::new("crawl and scan", "skipped", scrub(&skips.join("; "))));
                } else {
                    checks.push(CiCheck::new("crawl and scan", "passed", detail));
                }
            }
            ScanTaskStatus::Cancelled => {
                let why = self.budget_spent().unwrap_or_else(|| "the scan was cancelled".into());
                incomplete.push(format!("stopped before the scan finished: {why}"));
                checks.push(CiCheck::new("crawl and scan", "error", scrub(&why)));
            }
            _ => {
                let why = scrub(view.error.as_deref().unwrap_or("the scan task stopped"));
                incomplete.push(format!("the crawl and scan did not finish: {why}"));
                checks.push(CiCheck::new("crawl and scan", "error", why));
            }
        }
    }

    /// This run's findings: those created or touched since it started, not marked false positive, fixed or accepted.
    fn ci_findings(&self, since_ms: i64, scrub: &dyn Fn(&str) -> String) -> Result<Vec<CiFinding>> {
        let mut out = Vec::new();
        for f in self.finding_list(None)? {
            let status = f["status"].as_str().unwrap_or_default();
            if matches!(status, "false_positive" | "fixed" | "accepted_risk")
                || f["updated_ms"].as_i64().unwrap_or(0) < since_ms
            {
                continue;
            }
            let id = f["id"].as_i64().unwrap_or_default();
            let class = f["vuln_class"].as_str().unwrap_or_default();
            let title = f["title"].as_str().unwrap_or_default();
            let url_raw = f["url"].as_str().unwrap_or_default();
            let evidence: Vec<i64> = serde_json::from_value(f["evidence"].clone()).unwrap_or_default();
            let method = evidence
                .first()
                .and_then(|e| self.store.read(|db| db.get_exchange(*e)).ok().flatten())
                .map(|e| e.summary.method)
                .unwrap_or_default();
            let path = pm_model::template_path(&ci::path_of(url_raw)).0;
            let issue = crate::findings::issue_key(class);
            let point = ci::point_of_title(title);
            let key = ci::fingerprint_key(&issue, &method, &path, &point);
            let proven = PROVEN_STATUSES.contains(&status);
            let proof = proven
                .then(|| {
                    self.proofs_for_finding(id).ok().and_then(|ps| {
                        ps.into_iter().find(|p| p["proven"] == true).map(|p| CiProof {
                            oracle: p["oracle"].as_str().unwrap_or_default().to_string(),
                            confidence: p["confidence"].as_str().unwrap_or_default().to_string(),
                        })
                    })
                })
                .flatten();
            // The URL without its query: a query can carry tokens, and the path is what identifies the finding.
            let url = match url::Url::parse(url_raw) {
                Ok(mut u) => {
                    u.set_query(None);
                    u.set_fragment(None);
                    u.to_string()
                }
                Err(_) => ci::path_of(url_raw),
            };
            out.push(CiFinding {
                fingerprint: ci::fingerprint_id(&key),
                key: scrub(&key),
                issue,
                method,
                path: scrub(&path),
                point: scrub(&point),
                severity: f["severity"].as_str().unwrap_or("info").to_string(),
                status: if proven { "proven" } else { "suspected" }.into(),
                title: scrub(title),
                url: scrub(&url),
                proof,
                finding_id: id,
                state: String::new(),
                fails: false,
            });
        }
        Ok(out)
    }

    /// The SARIF file: the report's, with CI's fingerprints and baseline states (`pm_tools::ci::annotate_sarif`).
    fn ci_sarif(&self, summary: &CiSummary) -> Result<Value> {
        let report = self.report_with(&ReportOptions {
            min_severity: None,
            statuses: vec!["proven".into(), "suspected".into(), "confirmed".into(), "reported".into()],
            evidence: Some(false),
        })?;
        let mut sarif = crate::report::sarif(&report);
        ci::annotate_sarif(&mut sarif, summary);
        Ok(sarif)
    }
}
