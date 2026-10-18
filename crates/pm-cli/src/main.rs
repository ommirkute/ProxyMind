//! `proxymind`: command-line entry point.

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
    },
    /// Review actions waiting for human approval.
    Approvals {
        #[command(subcommand)]
        action: ApprovalAction,
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
        Command::History { limit, host, json } => {
            let store = Store::open(&cli.project)?;
            let rows = store.list_exchanges(*limit, host.as_deref())?;
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
        Command::Mcp { roe, actor } => {
            let actor = Actor::parse(actor)?;
            anyhow::ensure!(actor.kind != ActorKind::Human, "the MCP server acts for an agent; use agent:<name>");
            let service = Arc::new(open_service(&cli.project, roe.as_deref())?);
            eprintln!("ProxyMind MCP server for {} on project {}", actor.id(), cli.project.display());
            pm_mcp::McpServer::new(service, actor).serve_stdio().await?;
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
