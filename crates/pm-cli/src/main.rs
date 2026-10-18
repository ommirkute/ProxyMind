//! `proxymind`: command-line entry point.

mod bench;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pm_proxy::{Proxy, Recorder};
use pm_service::Service;
use pm_service::pm_policy::{ActionRequest, Actor, ActorKind, Decision, Policy, Roe, Target, Tier};
use pm_store::Store;
use pm_tls::CertAuthority;

/// Like `println!`, but returns write errors instead of panicking, so
/// `proxymind history | head` exits quietly when the pipe closes.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write;
        writeln!(std::io::stdout(), $($arg)*)?;
    }};
}

#[derive(Parser)]
#[command(name = "proxymind", version, about = "AI-native intercepting proxy for web pentesting")]
struct Cli {
    /// Project file (SQLite). Created if it does not exist.
    #[arg(long, short, global = true, default_value = "proxymind.pmproj", env = "PROXYMIND_PROJECT")]
    project: PathBuf,

    /// Directory for the CA and settings. Defaults to ~/.proxymind
    #[arg(long, global = true, env = "PROXYMIND_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the intercepting proxy.
    Proxy {
        #[arg(long, short, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Verify upstream TLS certificates (off by default for pentesting).
        #[arg(long)]
        verify_upstream: bool,
    },
    /// Manage the interception CA.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// List recorded exchanges, newest first.
    History {
        #[arg(long, short = 'n', default_value_t = 25)]
        limit: usize,
        /// Only show hosts containing this text.
        #[arg(long)]
        host: Option<String>,
        /// Only show paths containing this text.
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        method: Option<String>,
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show the raw request and response of one exchange.
    Show { id: i64 },
    /// Check and try out a rules-of-engagement (ROE) file.
    Roe {
        #[command(subcommand)]
        action: RoeAction,
    },
    /// Inspect the project's tamper-evident audit log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Run an MCP server on stdin/stdout so AI agents (e.g. Claude Code) can use ProxyMind.
    Mcp {
        /// Rules of engagement to use (saved to the project). Defaults to the project's saved ROE.
        #[arg(long)]
        roe: Option<PathBuf>,
        /// The agent's identity in the audit log, e.g. agent:claude
        #[arg(long, default_value = "agent:mcp")]
        actor: String,
        /// Also run an OAST callback listener on this address (e.g. 127.0.0.1:8085)
        #[arg(long)]
        oast_listen: Option<SocketAddr>,
        /// URL targets should call back (default: http://<oast-listen>)
        #[arg(long)]
        oast_public_url: Option<String>,
    },
    /// Start the web UI, the proxy and the API together.
    Ui {
        /// Where the UI and API listen (loopback only)
        #[arg(long, default_value = "127.0.0.1:7777")]
        listen: SocketAddr,
        /// Where the proxy listens; use --no-proxy to run without it
        #[arg(long, default_value = "127.0.0.1:8080")]
        proxy: SocketAddr,
        #[arg(long)]
        no_proxy: bool,
        /// Who you are in the audit log (default: human:<your username>)
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Run an out-of-band (OAST) callback listener that records interactions in the project.
    OastServer {
        #[arg(long, short, default_value = "127.0.0.1:8085")]
        listen: SocketAddr,
        /// URL targets should call back, e.g. http://oast.example.com:8085 (default: http://<listen>)
        #[arg(long)]
        public_url: Option<String>,
    },
    /// Show the application model built from traffic.
    Model {
        /// Only operations containing this text
        #[arg(long)]
        contains: Option<String>,
        /// Also list objects and their owners
        #[arg(long)]
        objects: bool,
        #[arg(long)]
        json: bool,
    },
    /// What has and hasn't been tested.
    Coverage {
        /// Include finished (confirmed/refuted) cells
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// List hypotheses.
    Hypotheses {
        #[arg(long)]
        status: Option<String>,
    },
    /// Review findings.
    Findings {
        #[command(subcommand)]
        action: FindingAction,
    },
    /// Inspect or re-run proofs.
    Proof {
        #[command(subcommand)]
        action: ProofAction,
    },
    /// Benchmarks: score this project's findings against an app's known vulnerabilities.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },
    /// Write a Markdown report of the findings.
    Report {
        /// Output file (default: print)
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Review actions waiting for human approval.
    Approvals {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    /// Manage test identities (users/roles and their sessions).
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Authorization checks: replay a request as other identities.
    Authz {
        #[command(subcommand)]
        action: AuthzAction,
    },
    /// Run VulnShop, a deliberately vulnerable demo API, on localhost.
    DemoTarget {
        #[arg(long, short, default_value = "127.0.0.1:8899")]
        listen: SocketAddr,
    },
}

#[derive(Subcommand)]
enum BenchAction {
    /// Compare findings with ground truth (default: VulnShop's).
    Score {
        /// Ground-truth YAML (see bench/ground-truth/vulnshop.yaml)
        #[arg(long)]
        truth: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum FindingAction {
    /// Record a suspected finding.
    Add {
        #[arg(long)]
        title: String,
        /// idor, bfla, sqli, ssrf, xss, …
        #[arg(long)]
        class: String,
        #[arg(long, default_value = "medium")]
        severity: String,
        #[arg(long, default_value = "")]
        description: String,
        /// Evidence exchange ids, comma-separated
        #[arg(long, value_delimiter = ',')]
        evidence: Vec<i64>,
    },
    /// List findings.
    List {
        #[arg(long)]
        status: Option<String>,
    },
    /// Show one finding with its proofs.
    Show { id: i64 },
    /// Mark a finding confirmed.
    Confirm { id: i64 },
    /// Mark a finding as a false positive.
    FalsePositive { id: i64 },
    /// Mark a finding as reported to the client.
    Reported { id: i64 },
}

#[derive(Subcommand)]
enum ProofAction {
    /// Prove broken access control: replay the owner's GET as another identity.
    Authz {
        exchange_id: i64,
        #[arg(long)]
        attacker: String,
        /// Owner identity (default: the one the exchange was made as)
        #[arg(long)]
        owner: Option<String>,
        /// Mark this finding proven if it succeeds
        #[arg(long)]
        finding: Option<i64>,
    },
    /// Prove time-based injection: compare the exchange's request with a delay payload.
    Timing {
        exchange_id: i64,
        /// File with the raw payload request
        #[arg(long)]
        payload_file: PathBuf,
        #[arg(long)]
        finding: Option<i64>,
    },
    /// Show a proof.
    Show { id: i64 },
    /// Run a proof again with the same inputs (e.g. during a retest).
    Rerun { id: i64 },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// List identities (credential names only, never values).
    List,
    /// Create or update an identity from the cookies/auth headers of a recorded request.
    Capture {
        name: String,
        #[arg(long)]
        from: i64,
        #[arg(long, default_value = "user")]
        role: String,
    },
    /// Use a recorded GET (e.g. /api/me) as the identity's session health check.
    Health {
        name: String,
        #[arg(long)]
        from: i64,
        /// Text the response must contain while logged in (e.g. the user's email)
        #[arg(long)]
        expect_contains: Option<String>,
        #[arg(long)]
        expect_status: Option<u16>,
    },
    /// Use a recorded login request as the identity's login recipe.
    Login {
        name: String,
        #[arg(long)]
        from: i64,
        /// JSON pointer to a token in the login response, e.g. /token (sent as Authorization: Bearer)
        #[arg(long)]
        token_pointer: Option<String>,
    },
    /// Define an identity from a JSON file (name, role, auth, health, login).
    Set {
        file: PathBuf,
    },
    /// Check an identity's session (logs in again if needed).
    Check {
        name: String,
    },
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum AuthzAction {
    /// Re-send a recorded GET as other identities and compare with the owner's response.
    Check {
        exchange_id: i64,
        /// Comma-separated identity names, e.g. bob,admin
        #[arg(long = "as", value_delimiter = ',')]
        identities: Vec<String>,
        #[arg(long)]
        no_anonymous: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show the latest results.
    Results {
        #[arg(long)]
        exchange: Option<i64>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ApprovalAction {
    /// List approvals (pending only, unless --all).
    List {
        #[arg(long)]
        all: bool,
    },
    /// Approve a pending action.
    Approve {
        id: String,
        /// Who is approving (default: human:<your username>)
        #[arg(long = "as")]
        approver: Option<String>,
    },
    /// Deny a pending action.
    Deny {
        id: String,
        #[arg(long = "as")]
        approver: Option<String>,
    },
    /// Wait for new approval requests and ask about each one.
    Watch {
        #[arg(long = "as")]
        approver: Option<String>,
    },
}

#[derive(Subcommand)]
enum RoeAction {
    /// Validate an ROE file and print a summary.
    Check { file: PathBuf },
    /// Save an ROE file into the project, so the MCP server and approvals use it.
    Use { file: PathBuf },
    /// Print the ROE saved in the project.
    Show,
    /// Show what the policy gate would decide for a request (nothing is sent or recorded).
    Test {
        file: PathBuf,
        /// Full URL, e.g. https://app.example.com/api/users
        url: String,
        /// Who is acting: human:<name>, agent:<name>, plugin:<name> or scanner:<name>
        #[arg(long, default_value = "agent:test")]
        actor: String,
        /// HTTP method; sets the tier (GET = active_safe, DELETE = destructive, others = active_intrusive)
        #[arg(long, default_value = "GET")]
        method: String,
        /// Override the tier: read, passive, active_safe, active_intrusive, destructive
        #[arg(long)]
        tier: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Check that no audit record was changed, removed or reordered.
    Verify,
    /// List audit records, newest first.
    List {
        #[arg(long, short = 'n', default_value_t = 25)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CaAction {
    /// Print the path of the CA certificate to install in your browser.
    Path,
    /// Print the CA certificate (PEM).
    Export,
}

fn home_dir(cli: &Cli) -> Result<PathBuf> {
    if let Some(h) = &cli.home {
        return Ok(h.clone());
    }
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .context("cannot find a home directory; pass --home")?;
    Ok(PathBuf::from(base).join(".proxymind"))
}

const ROE_SETTING: &str = "roe";

/// Opens the project's service with its saved ROE, or saves `roe_file` first.
fn open_service(project: &std::path::Path, roe_file: Option<&std::path::Path>) -> Result<Service> {
    let mut store = Store::open(project)?;
    let text = match roe_file {
        Some(f) => {
            let text = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
            Roe::parse(&text)?;
            store.set_setting(ROE_SETTING, &text)?;
            text
        }
        None => store.get_setting(ROE_SETTING)?.context(
            "this project has no rules of engagement yet; run `proxymind roe use <file>` (see examples/roe.yaml)",
        )?,
    };
    Ok(Service::new(store, Policy::new(Roe::parse(&text)?))?)
}

fn human_actor(given: Option<&str>) -> Result<Actor> {
    let id = match given {
        Some(g) => g.to_string(),
        None => {
            let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "local".into());
            let user: String = user.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).collect();
            format!("human:{}", if user.is_empty() { "local".into() } else { user })
        }
    };
    let actor = Actor::parse(&id)?;
    anyhow::ensure!(actor.kind == ActorKind::Human, "only human:<name> actors can approve");
    Ok(actor)
}

/// Starts the OAST listener in this process, recording into the project.
async fn start_oast(service: &Arc<Service>, addr: SocketAddr, public: Option<String>) -> Result<()> {
    let public = public.unwrap_or_else(|| format!("http://{addr}"));
    service.set_oast_public_url(&public)?;
    let l = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding OAST listener on {addr}"))?;
    let s = service.clone();
    tokio::spawn(pm_oast::serve(l, move |i| {
        if let Err(e) = s.record_oast(&i) {
            eprintln!("could not record OAST interaction: {e}");
        }
    }));
    eprintln!("OAST listener on {addr}; payloads will call back to {public}");
    Ok(())
}

fn print_approval(a: &pm_service::ApprovalRow) -> Result<()> {
    out!("{}  [{}]  {}  by {}  ({})", a.id, a.status, a.summary, a.actor, a.tier);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&a.params)
        && let Some(req) = v.get("request").and_then(|r| r.as_str())
    {
        for line in req.lines().take(30) {
            out!("    | {line}");
        }
    }
    if let Some(by) = &a.decided_by {
        out!("    decided by {by}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) if is_broken_pipe(&e) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,pm_proxy=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match &cli.command {
        Command::Proxy { listen, verify_upstream } => {
            let ca = Arc::new(CertAuthority::load_or_create(&home_dir(&cli)?)?);
            let store = Store::open(&cli.project)?;
            let (recorder, writer) = Recorder::spawn(store);
            let proxy = Proxy::new(ca.clone(), recorder, *verify_upstream)?;
            let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
            eprintln!("ProxyMind listening on http://{listen}");
            eprintln!("Project: {}", cli.project.display());
            eprintln!("CA certificate (install in your browser): {}", ca.ca_cert_path().display());
            tokio::select! {
                r = proxy.run(listener) => r?,
                _ = tokio::signal::ctrl_c() => eprintln!("\nShutting down"),
            }
            // Recorder senders live inside spawned tasks; give in-flight
            // records a moment, then let the process exit.
            drop(writer);
        }
        Command::Ca { action } => {
            let ca = CertAuthority::load_or_create(&home_dir(&cli)?)?;
            match action {
                CaAction::Path => out!("{}", ca.ca_cert_path().display()),
                CaAction::Export => {
                    use std::io::Write;
                    write!(std::io::stdout(), "{}", ca.ca_pem())?;
                }
            }
        }
        Command::History { limit, host, path, method, json } => {
            let store = Store::open(&cli.project)?;
            let rows = store.search_exchanges(&pm_store::HistoryFilter {
                host: host.clone(),
                path: path.clone(),
                method: method.clone(),
                limit: Some(*limit),
                ..Default::default()
            })?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                out!("{:>6}  {:<7} {:>6}  {:>9}  {:<30} PATH", "ID", "METHOD", "STATUS", "BYTES", "HOST");
                for r in rows {
                    let status = r.status.map_or_else(|| "ERR".to_string(), |s| s.to_string());
                    let bytes = r.resp_len.map_or_else(|| "-".to_string(), |b| b.to_string());
                    let path: String = r.path.chars().take(80).collect();
                    out!("{:>6}  {:<7} {:>6}  {:>9}  {:<30} {}", r.id, r.method, status, bytes, r.host, path);
                }
            }
        }
        Command::Roe { action: RoeAction::Check { file } } => {
            let roe = Roe::load(file)?;
            out!("✓ {} is valid", file.display());
            if let Some(name) = &roe.engagement.name {
                out!("  Engagement: {name}");
            }
            if roe.engagement.starts.is_some() || roe.engagement.ends.is_some() {
                let d = |x: Option<jiff::civil::Date>| x.map_or("-".to_string(), |d| d.to_string());
                out!("  Dates:      {} to {}", d(roe.engagement.starts), d(roe.engagement.ends));
            }
            out!("  In scope:   {}", roe.include.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(", "));
            if !roe.exclude.is_empty() {
                out!("  Excluded:   {}", roe.exclude.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(", "));
            }
            if !roe.deny_networks.is_empty() {
                let nets: Vec<String> = roe.deny_networks.iter().map(ToString::to_string).collect();
                out!("  Denied networks: {}", nets.join(", "));
            }
            out!(
                "  Limits:     {} req/s per host, {} concurrent",
                roe.limits.max_rps_per_host,
                roe.limits.max_concurrency
            );
            out!(
                "  Data:       redact before LLM = {}, cloud models allowed = {}",
                roe.data.redact_before_llm,
                roe.data.allow_cloud_models
            );
            out!("  Agents:     {}", tier_line(&roe, ActorKind::Agent));
            out!("  Humans:     {}", tier_line(&roe, ActorKind::Human));
        }
        Command::Roe { action: RoeAction::Test { file, url, actor, method, tier } } => {
            let roe = Roe::load(file)?;
            let tier = match tier {
                Some(t) => Tier::parse(t).with_context(|| format!("unknown tier {t:?}"))?,
                None => Tier::for_http_method(method),
            };
            let req = ActionRequest {
                actor: Actor::parse(actor)?,
                action: "replay_send".into(),
                tier,
                target: Some(Target::from_url(url)?),
                summary: format!("{method} {url}"),
            };
            let service = Service::new(Store::open_in_memory()?, Policy::new(roe))?;
            let v = service.dry_run(&req);
            let label = match v.decision {
                Decision::Allow => "ALLOW",
                Decision::Approve => "NEEDS APPROVAL",
                Decision::Deny => "DENY",
            };
            out!("{label}: {} {url} as {actor} ({tier:?})", method.to_uppercase());
            for r in v.reasons {
                out!("  - {r}");
            }
        }
        Command::Roe { action: RoeAction::Use { file } } => {
            open_service(&cli.project, Some(file))?;
            out!("✓ {} is now the rules of engagement for {}", file.display(), cli.project.display());
        }
        Command::Roe { action: RoeAction::Show } => {
            let store = Store::open(&cli.project)?;
            match store.get_setting(ROE_SETTING)? {
                Some(t) => out!("{t}"),
                None => out!("No rules of engagement saved. Run `proxymind roe use <file>`."),
            }
        }
        Command::Mcp { roe, actor, oast_listen, oast_public_url } => {
            let actor = Actor::parse(actor)?;
            anyhow::ensure!(actor.kind != ActorKind::Human, "the MCP server acts for an agent; use agent:<name>");
            let service = Arc::new(open_service(&cli.project, roe.as_deref())?);
            if let Some(addr) = oast_listen {
                start_oast(&service, *addr, oast_public_url.clone()).await?;
            }
            eprintln!("ProxyMind MCP server for {} on project {}", actor.id(), cli.project.display());
            pm_mcp::McpServer::new(service, actor).serve_stdio().await?;
        }
        Command::Ui { listen, proxy, no_proxy, actor } => {
            anyhow::ensure!(listen.ip().is_loopback(), "the UI/API must listen on a loopback address");
            let home = home_dir(&cli)?;
            let token = pm_api::load_or_create_token(&home.join("api-token"))?;
            let service = Arc::new(open_service(&cli.project, None)?);
            let me = human_actor(actor.as_deref())?;
            if !*no_proxy {
                let ca = Arc::new(CertAuthority::load_or_create(&home)?);
                let (recorder, _writer) = Recorder::spawn(Store::open(&cli.project)?);
                let queue = Arc::new(pm_proxy::InterceptQueue::new());
                service.attach_intercept(queue.clone());
                let p = Proxy::with_intercept(ca.clone(), recorder, false, Some(queue))?;
                let l =
                    tokio::net::TcpListener::bind(proxy).await.with_context(|| format!("binding proxy on {proxy}"))?;
                tokio::spawn(p.run(l));
                eprintln!("Proxy on http://{proxy} (CA: {})", ca.ca_cert_path().display());
            }
            let state = pm_api::AppState {
                service,
                actor: me.clone(),
                token: Arc::new(token.clone()),
                project: Arc::new(cli.project.display().to_string()),
            };
            let l = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding UI on {listen}"))?;
            eprintln!("ProxyMind UI for {} on project {}", me.id(), cli.project.display());
            out!("Open: http://{listen}/auth?token={token}");
            tokio::select! {
                r = axum::serve(l, pm_api::router(state)) => r?,
                _ = tokio::signal::ctrl_c() => eprintln!("\nShutting down"),
            }
        }
        Command::OastServer { listen, public_url } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            start_oast(&service, *listen, public_url.clone()).await?;
            tokio::signal::ctrl_c().await?;
        }
        Command::Model { contains, objects, json } => {
            let service = open_service(&cli.project, None)?;
            let m = service.model_get(&pm_service::ModelFilter {
                contains: contains.clone(),
                include_objects: Some(*objects),
                object_type: None,
            })?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&m)?);
            } else {
                out!("{:<8} {:<16} {:>5}  {:<24} OPERATION", "METHOD", "KIND", "SEEN", "IDENTITIES");
                for o in m["operations"].as_array().into_iter().flatten() {
                    let ids: Vec<&str> =
                        o["identities"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect();
                    out!(
                        "{:<8} {:<16} {:>5}  {:<24} {}{}",
                        o["method"].as_str().unwrap_or(""),
                        o["kind"].as_str().unwrap_or(""),
                        o["count"],
                        ids.join(","),
                        o["origin"].as_str().unwrap_or(""),
                        o["template"].as_str().unwrap_or("")
                    );
                }
                for ob in m["objects"].as_array().into_iter().flatten() {
                    out!(
                        "  {} {}  owner={} ({})",
                        ob["object_type"].as_str().unwrap_or(""),
                        ob["id"].as_str().unwrap_or(""),
                        ob["owner"].as_str().unwrap_or("?"),
                        ob["owner_source"].as_str().unwrap_or("-")
                    );
                }
            }
        }
        Command::Coverage { all, json } => {
            let service = open_service(&cli.project, None)?;
            let c = service.coverage(!all)?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&c)?);
            } else {
                out!("{}% tested · {:?}", c.percent_tested, c.totals);
                for cell in &c.cells {
                    let param = if cell.param.is_empty() { String::new() } else { format!(" [{}]", cell.param) };
                    out!("{:<10} {:<16} {}{}", cell.status, cell.vuln_class, cell.operation, param);
                }
            }
        }
        Command::Hypotheses { status } => {
            let service = open_service(&cli.project, None)?;
            for h in service.hypothesis_list(status.as_deref())? {
                out!(
                    "#{:<4} {:<10} {:<16} {}  — {} ({})",
                    h.id,
                    h.status,
                    h.vuln_class,
                    h.operation,
                    h.rationale,
                    h.actor
                );
            }
        }
        Command::Findings { action } => {
            let service = open_service(&cli.project, None)?;
            let me = human_actor(None)?;
            let set = |id: i64, st: &str| {
                service.finding_update(
                    &me,
                    pm_service::FindingUpdate {
                        id,
                        status: Some(st.into()),
                        severity: None,
                        description: None,
                        add_evidence: vec![],
                    },
                )
            };
            match action {
                FindingAction::Add { title, class, severity, description, evidence } => {
                    let f = service.finding_create(
                        &me,
                        pm_service::NewFinding {
                            title: title.clone(),
                            vuln_class: class.clone(),
                            severity: severity.clone(),
                            description: description.clone(),
                            url: None,
                            evidence: evidence.clone(),
                            hypothesis_id: None,
                        },
                    )?;
                    out!("✓ finding #{} recorded as {}", f["id"], f["status"]);
                }
                FindingAction::List { status } => {
                    for f in service.finding_list(status.as_deref())? {
                        out!(
                            "#{:<4} {:<9} {:<15} {}  {}",
                            f["id"],
                            f["severity"].as_str().unwrap_or(""),
                            f["status"].as_str().unwrap_or(""),
                            f["title"].as_str().unwrap_or(""),
                            f["url"].as_str().unwrap_or("")
                        );
                    }
                }
                FindingAction::Show { id } => out!("{}", serde_json::to_string_pretty(&service.finding_get(*id)?)?),
                FindingAction::Confirm { id } => out!("finding {} is now {}", id, set(*id, "confirmed")?["status"]),
                FindingAction::FalsePositive { id } => {
                    out!("finding {} is now {}", id, set(*id, "false_positive")?["status"])
                }
                FindingAction::Reported { id } => out!("finding {} is now {}", id, set(*id, "reported")?["status"]),
            }
        }
        Command::Proof { action } => {
            let service = open_service(&cli.project, None)?;
            let print_result = |r: &pm_service::ProofResult| -> Result<()> {
                match r {
                    pm_service::ProofResult::Completed { proof_id, proven, confidence, reasons, .. } => {
                        out!(
                            "{} (proof #{proof_id}, {confidence} confidence)",
                            if *proven { "✓ PROVEN" } else { "✗ not proven" }
                        );
                        for r in reasons {
                            out!("  - {r}");
                        }
                    }
                    other => out!("{}", serde_json::to_string_pretty(other)?),
                }
                Ok(())
            };
            match action {
                ProofAction::Authz { exchange_id, attacker, owner, finding } => {
                    let r = service
                        .proof_run(
                            &human_actor(None)?,
                            pm_service::ProofRequest {
                                oracle: "differential_authz".into(),
                                exchange_id: Some(*exchange_id),
                                attacker: Some(attacker.clone()),
                                owner: owner.clone(),
                                finding_id: *finding,
                                ..Default::default()
                            },
                        )
                        .await?;
                    print_result(&r)?;
                }
                ProofAction::Timing { exchange_id, payload_file, finding } => {
                    let payload = std::fs::read_to_string(payload_file)?;
                    let r = service
                        .proof_run(
                            &human_actor(None)?,
                            pm_service::ProofRequest {
                                oracle: "timing".into(),
                                exchange_id: Some(*exchange_id),
                                payload_raw: Some(payload),
                                finding_id: *finding,
                                ..Default::default()
                            },
                        )
                        .await?;
                    print_result(&r)?;
                }
                ProofAction::Show { id } => out!("{}", serde_json::to_string_pretty(&service.proof_get(*id)?)?),
                ProofAction::Rerun { id } => {
                    let r = service.proof_rerun(&human_actor(None)?, *id).await?;
                    out!("{}", serde_json::to_string_pretty(&r)?);
                }
            }
        }
        Command::Bench { action: BenchAction::Score { truth, json } } => {
            let service = open_service(&cli.project, None)?;
            let truth = bench::load_truth(truth.as_deref())?;
            let score = bench::score(&truth, &service.finding_list(None)?);
            if *json {
                out!("{}", serde_json::to_string_pretty(&score)?);
            } else {
                out!("{}: found {}/{}, proven {}/{}", score.app, score.found, score.total, score.proven, score.total);
                for v in &score.vulns {
                    let mark = if v.proven {
                        "✓ proven"
                    } else if v.found {
                        "~ found "
                    } else {
                        "✗ missed"
                    };
                    out!("  {mark}  {:<5} {:<6} {}  findings {:?}", v.id, v.class, v.endpoint, v.findings);
                }
                if !score.findings_on_secure_endpoints.is_empty() {
                    out!("  false positives on secure endpoints: {:?}", score.findings_on_secure_endpoints);
                }
                if !score.unmatched_findings.is_empty() {
                    out!("  findings matching no known vulnerability: {:?}", score.unmatched_findings);
                }
            }
        }
        Command::Report { out: file } => {
            let service = open_service(&cli.project, None)?;
            let md = service.report_markdown()?;
            match file {
                Some(f) => {
                    std::fs::write(f, md)?;
                    out!("✓ report written to {}", f.display());
                }
                None => out!("{md}"),
            }
        }
        Command::Approvals { action } => {
            let service = open_service(&cli.project, None)?;
            match action {
                ApprovalAction::List { all } => {
                    let rows = service.approvals(if *all { None } else { Some("pending") }, 100)?;
                    if rows.is_empty() {
                        out!("No {}approvals.", if *all { "" } else { "pending " });
                    }
                    for a in &rows {
                        print_approval(a)?;
                    }
                }
                ApprovalAction::Approve { id, approver } => {
                    let a = service.decide_approval(id, &human_actor(approver.as_deref())?, true)?;
                    out!("✓ approved {} ({})", a.id, a.summary);
                }
                ApprovalAction::Deny { id, approver } => {
                    let a = service.decide_approval(id, &human_actor(approver.as_deref())?, false)?;
                    out!("✗ denied {} ({})", a.id, a.summary);
                }
                ApprovalAction::Watch { approver } => {
                    let me = human_actor(approver.as_deref())?;
                    out!("Watching {} for approval requests as {} (Ctrl+C to stop)…", cli.project.display(), me.id());
                    let mut seen = std::collections::HashSet::new();
                    loop {
                        for a in service.approvals(Some("pending"), 100)?.into_iter().rev() {
                            if !seen.insert(a.id.clone()) {
                                continue;
                            }
                            out!("");
                            print_approval(&a)?;
                            let answer = tokio::task::spawn_blocking(|| {
                                use std::io::Write;
                                print!("Approve? [y/N] ");
                                let _ = std::io::stdout().flush();
                                let mut line = String::new();
                                std::io::stdin().read_line(&mut line).map(|_| line)
                            })
                            .await??;
                            let yes = matches!(answer.trim(), "y" | "Y" | "yes");
                            match service.decide_approval(&a.id, &me, yes) {
                                Ok(_) => out!("{} {}", if yes { "✓ approved" } else { "✗ denied" }, a.id),
                                Err(e) => out!("could not decide {}: {e}", a.id),
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Command::Identity { action } => {
            let service = open_service(&cli.project, None)?;
            let me = human_actor(None)?;
            let show = |i: &pm_service::IdentityInfo| -> Result<()> {
                out!(
                    "{:<12} role={:<8} status={:<10} cookies=[{}] headers=[{}] health={} login={}",
                    i.name,
                    i.role,
                    i.status,
                    i.cookies.join(","),
                    i.headers.join(","),
                    if i.has_health_check { "yes" } else { "no" },
                    if i.has_login { "yes" } else { "no" }
                );
                Ok(())
            };
            match action {
                IdentityAction::List => {
                    let list = service.identity_list()?;
                    if list.is_empty() {
                        out!(
                            "No identities. Capture one with `proxymind identity capture <name> --from <exchange-id>`."
                        );
                    }
                    for i in &list {
                        show(i)?;
                    }
                }
                IdentityAction::Capture { name, from, role } => {
                    show(&service.identity_capture(&me, name, role, *from)?)?
                }
                IdentityAction::Health { name, from, expect_contains, expect_status } => show(
                    &service.identity_set_health_from(&me, name, *from, expect_contains.clone(), *expect_status)?,
                )?,
                IdentityAction::Login { name, from, token_pointer } => {
                    show(&service.identity_set_login_from(&me, name, *from, token_pointer.clone())?)?
                }
                IdentityAction::Set { file } => {
                    let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
                    let ident: pm_service::pm_identity::Identity = serde_json::from_str(&text)?;
                    show(&service.identity_set(&me, ident)?)?
                }
                IdentityAction::Check { name } => {
                    let c = service.identity_check(&me, name).await?;
                    out!("{}: {}", c.name, c.status);
                    for n in c.notes {
                        out!("  - {n}");
                    }
                }
                IdentityAction::Delete { name } => {
                    let deleted = service.identity_delete(&me, name)?;
                    out!("{}", if deleted { format!("deleted {name}") } else { format!("no identity {name}") });
                }
            }
        }
        Command::Authz { action } => {
            let service = open_service(&cli.project, None)?;
            let print = |rows: &[pm_service::pm_store::AuthzRow]| -> Result<()> {
                out!(
                    "{:>6}  {:<12} {:<18} {:>6}  {:>6}  {:>8}  SUMMARY",
                    "EXCH",
                    "IDENTITY",
                    "VERDICT",
                    "STATUS",
                    "SIM",
                    "EVIDENCE"
                );
                for r in rows {
                    out!(
                        "{:>6}  {:<12} {:<18} {:>6}  {:>6}  {:>8}  {} {}  {}",
                        r.exchange_id,
                        r.identity,
                        r.verdict,
                        r.status.map_or("-".into(), |s| s.to_string()),
                        r.similarity.map_or("-".into(), |s| format!("{s:.2}")),
                        r.evidence_id.map_or("-".into(), |s| s.to_string()),
                        r.method,
                        r.url,
                        r.summary
                    );
                }
                Ok(())
            };
            match action {
                AuthzAction::Check { exchange_id, identities, no_anonymous, json } => {
                    let report = service
                        .authz_check(
                            &human_actor(None)?,
                            pm_service::AuthzCheckRequest {
                                exchange_id: *exchange_id,
                                identities: identities.clone(),
                                include_anonymous: Some(!no_anonymous),
                            },
                        )
                        .await?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        out!(
                            "{} {} (owner's request re-sent: {})",
                            report.method,
                            report.url,
                            report.baseline_status.map_or("no response".to_string(), |s| s.to_string())
                        );
                        print(&report.results)?;
                    }
                }
                AuthzAction::Results { exchange, json } => {
                    let rows = service.authz_results(*exchange)?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&rows)?);
                    } else {
                        print(&rows)?;
                    }
                }
            }
        }
        Command::DemoTarget { listen } => {
            anyhow::ensure!(
                listen.ip().is_loopback(),
                "VulnShop is deliberately vulnerable; bind it to 127.0.0.1 only"
            );
            let l = tokio::net::TcpListener::bind(listen).await?;
            eprintln!("VulnShop (deliberately vulnerable) on http://{listen}");
            eprintln!("Users: alice/alice123, bob/bob123, admin/admin123. Log in with POST /api/login.");
            pm_demo::VulnShop::new().serve(l).await;
        }
        Command::Audit { action: AuditAction::Verify } => {
            let store = Store::open(&cli.project)?;
            let n = pm_service::verify_audit(&store)?;
            out!("✓ audit log intact: {n} records, chain verified");
        }
        Command::Audit { action: AuditAction::List { limit, json } } => {
            let store = Store::open(&cli.project)?;
            let mut records = store.audit_records()?;
            records.reverse();
            records.truncate(*limit);
            if *json {
                out!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                out!("{:>6}  {:<24} {:<18} {:<20} DETAIL", "SEQ", "ACTOR", "ACTION", "DECISION");
                for r in records {
                    let detail: String = r.detail.chars().take(80).collect();
                    out!("{:>6}  {:<24} {:<18} {:<20} {}", r.seq, r.actor, r.action, r.decision, detail);
                }
            }
        }
        Command::Show { id } => {
            let store = Store::open(&cli.project)?;
            let ex = store.get_exchange(*id)?.with_context(|| format!("no exchange with id {id}"))?;
            out!("{}", String::from_utf8_lossy(&ex.request));
            out!("----------------------------------------");
            match ex.response {
                Some(r) => out!("{}", String::from_utf8_lossy(&r)),
                None => out!("(no response: {})", ex.summary.error.unwrap_or_default()),
            }
        }
    }
    Ok(())
}

fn tier_line(roe: &Roe, actor: ActorKind) -> String {
    [Tier::Read, Tier::Passive, Tier::ActiveSafe, Tier::ActiveIntrusive, Tier::Destructive]
        .iter()
        .map(|&t| {
            let name = serde_json::to_value(t).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
            format!("{name}={}", roe.tier_decision(actor, t).as_str())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe))
}
