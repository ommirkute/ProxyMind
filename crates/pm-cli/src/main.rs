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
        /// Speak only HTTP/1.1 to browsers (HTTP/2 is offered by default).
        #[arg(long)]
        no_http2: bool,
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
    /// Find text in recorded requests and responses (decoded bodies included).
    Search {
        query: String,
        /// Treat the query as a regular expression
        #[arg(long)]
        regex: bool,
        #[arg(long)]
        case_sensitive: bool,
        /// both, request, response, headers, bodies, request_headers, request_body, response_headers or
        /// response_body
        #[arg(long, default_value = "both")]
        part: String,
        /// List exchanges that do NOT match
        #[arg(long)]
        invert: bool,
        /// Only in-scope exchanges
        #[arg(long)]
        in_scope: bool,
        /// Only hosts containing this text
        #[arg(long)]
        host: Option<String>,
        /// Most hits
        #[arg(long, short = 'n', default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Recorded traffic as a tree per origin.
    Sitemap {
        /// Only hosts containing this text
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Check and try out a rules-of-engagement (ROE) file.
    Roe {
        #[command(subcommand)]
        action: RoeAction,
    },
    /// Match-and-replace rules the proxy applies to live traffic.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// The built-in AI assistant (local model by default).
    Assistant {
        #[command(subcommand)]
        action: AssistantAction,
    },
    /// Upstream proxy and client certificates for outgoing connections.
    Network {
        #[command(subcommand)]
        action: NetworkAction,
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
        /// Speak only HTTP/1.1 to browsers (HTTP/2 is offered by default).
        #[arg(long)]
        no_http2: bool,
        /// Who you are in the audit log (default: human:<your username>)
        #[arg(long = "as")]
        actor: Option<String>,
        /// Allow the UI/API to listen on a non-loopback address. Only for a
        /// container whose port is published on the host's loopback
        /// (docker run -p 127.0.0.1:7777:7777); requests must still be
        /// addressed to localhost and carry the token.
        #[arg(long)]
        bind_any: bool,
        /// Also open a browser window that goes through the proxy (its own
        /// profile; trusts ProxyMind's CA without installing it)
        #[arg(long)]
        open_browser: bool,
    },
    /// Run an out-of-band (OAST) callback listener that records interactions in the project.
    OastServer {
        #[arg(long, short, default_value = "127.0.0.1:8085")]
        listen: SocketAddr,
        /// URL targets should call back, e.g. http://oast.example.com:8085 (default: http://<listen>)
        #[arg(long)]
        public_url: Option<String>,
        /// Also answer DNS on this UDP address (e.g. 0.0.0.0:53); needs --domain
        #[arg(long, requires = "domain")]
        dns: Option<SocketAddr>,
        /// Domain delegated to this server (NS record), e.g. oast.example.com
        #[arg(long, requires = "dns")]
        domain: Option<String>,
        /// IPv4 address A queries are answered with (default: the HTTP listener's address, or 127.0.0.1)
        #[arg(long)]
        dns_answer: Option<std::net::Ipv4Addr>,
        /// Also take mail on this address (e.g. 0.0.0.0:25): mail to a payload address is an interaction
        #[arg(long)]
        smtp: Option<SocketAddr>,
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
    /// Passive scan of recorded traffic (sends nothing): leads to test, not findings.
    Scan {
        /// Only hosts containing this
        #[arg(long)]
        host: Option<String>,
        /// info, low, medium or high
        #[arg(long)]
        min_severity: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Active checks on one recorded request (SQL injection: error, boolean and time based; command
    /// injection; reflection, open redirect, traversal, SSTI), in parameters, cookies and headers.
    ScanActive {
        exchange_id: i64,
        /// Only these checks (repeatable)
        #[arg(long = "check")]
        checks: Vec<String>,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Import an OpenAPI 3 / Swagger 2 description.
    Openapi {
        /// Spec file (JSON or YAML); or use --exchange
        file: Option<PathBuf>,
        /// A recorded exchange whose response is the spec
        #[arg(long, conflicts_with = "file")]
        exchange: Option<i64>,
        /// scheme://host[:port][/base] when the spec's servers aren't absolute
        #[arg(long)]
        base_url: Option<String>,
        /// Send each GET example once (in scope only) so the model learns them
        #[arg(long)]
        send: bool,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Read a GraphQL schema (introspection) and list its operations with example requests.
    Graphql {
        /// The endpoint, e.g. https://app.example.com/graphql
        #[arg(long)]
        url: Option<String>,
        /// An introspection result (JSON file)
        #[arg(long, conflicts_with_all = ["exchange", "fetch"])]
        schema: Option<PathBuf>,
        /// A recorded exchange whose response is an introspection result
        #[arg(long, conflicts_with = "fetch")]
        exchange: Option<i64>,
        /// Send the introspection query to --url (in scope only)
        #[arg(long, requires = "url")]
        fetch: bool,
        #[arg(long)]
        identity: Option<String>,
        /// Print each operation's example request
        #[arg(long)]
        examples: bool,
        #[arg(long)]
        json: bool,
    },
    /// Add the exchanges of a HAR file (browser devtools export) to history. Sends nothing.
    Import {
        /// The .har file
        file: PathBuf,
    },
    /// Write history as a HAR file (newest first).
    Export {
        /// Output file (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Only these exchange ids (repeatable)
        #[arg(long = "id")]
        ids: Vec<i64>,
        /// Host contains
        #[arg(long)]
        host: Option<String>,
        /// Most exchanges to write
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Print a curl command for a recorded exchange, or (--parse) read one into a raw request.
    Curl {
        /// Exchange id
        #[arg(required_unless_present = "parse")]
        exchange_id: Option<i64>,
        /// Read a curl command (or - for stdin) and print the raw request
        #[arg(long, conflicts_with = "exchange_id")]
        parse: Option<String>,
    },
    /// Encode or decode text locally (no ops: smart decode).
    Decode {
        input: String,
        /// Operation, repeatable and applied in order (e.g. --op url_decode --op base64_decode)
        #[arg(long = "op")]
        ops: Vec<String>,
    },
    /// Compare two recorded exchanges.
    Compare { a: i64, b: i64 },
    /// Token randomness: re-send a token-issuing request and analyse the tokens.
    TokenAnalyzer {
        exchange_id: i64,
        /// cookie:<name>, header:<name>, json:/pointer or between:<a>|<b>
        #[arg(long)]
        locator: String,
        #[arg(long, default_value_t = 100)]
        samples: usize,
        #[arg(long)]
        identity: Option<String>,
    },
    /// Look for hidden files and folders under a URL (GET only, in scope only).
    Discover {
        url: String,
        /// Word list file (one path per line); default: the built-in list
        #[arg(long)]
        wordlist: Option<PathBuf>,
        /// Also use the built-in list with --wordlist
        #[arg(long)]
        builtin: bool,
        /// Extensions to try on words without one (repeatable), e.g. -x bak -x old
        #[arg(long = "ext", short = 'x')]
        extensions: Vec<String>,
        #[arg(long, default_value_t = 500)]
        max_requests: usize,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Crawl from a URL (GET only, in scope only, skipping links that log out or delete).
    Crawl {
        url: String,
        #[arg(long, default_value_t = 50)]
        max_pages: usize,
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Don't read robots.txt and sitemaps
        #[arg(long)]
        no_robots: bool,
        #[arg(long)]
        identity: Option<String>,
        /// Load pages in a headless browser that runs their JavaScript
        /// (single-page apps); every request still goes through the policy gate
        #[arg(long)]
        browser: bool,
        #[arg(long)]
        json: bool,
    },
    /// Install, list or remove passive-check plugins (per user, never per project).
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },
    /// Lock (encrypt) or unlock a project file with a passphrase.
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Fuzz a request: payloads in positions marked §like this§, anomalies pointed out.
    Fuzzer {
        /// Target as scheme://host[:port] (or use --exchange)
        #[arg(long, required_unless_present = "exchange")]
        url: Option<String>,
        /// Recorded exchange whose target to use
        #[arg(long)]
        exchange: Option<i64>,
        /// File with the raw request, positions marked §like this§
        #[arg(long)]
        raw_file: PathBuf,
        /// one_at_a_time, same_everywhere, paired or all_combinations
        #[arg(long, default_value = "one_at_a_time")]
        mode: String,
        /// A payload file (one payload per line); repeat for one set per position
        #[arg(long = "payloads")]
        payload_files: Vec<PathBuf>,
        /// Numbers as a payload set, e.g. 1000-1050 or 0-100:10
        #[arg(long)]
        numbers: Option<String>,
        /// A built-in payload list: ids, sqli, xss, traversal, ssti, methods_override
        #[arg(long)]
        builtin: Option<String>,
        /// Percent-encode payloads
        #[arg(long)]
        url_encode: bool,
        /// Flag responses containing this text (repeatable)
        #[arg(long)]
        grep: Vec<String>,
        /// Send with this identity's credentials
        #[arg(long)]
        identity: Option<String>,
        /// Print JSON
        #[arg(long)]
        json: bool,
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
        /// Output file (default: print; a PDF needs one)
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// md, html, pdf, json or sarif (default: from --out's extension, else md)
        #[arg(long)]
        format: Option<String>,
        /// technical (default), executive, compliance or a saved template
        #[arg(long)]
        template: Option<String>,
        /// Leave out findings below this severity
        #[arg(long)]
        min_severity: Option<String>,
        /// Leave out request/response evidence
        #[arg(long)]
        no_evidence: bool,
    },
    /// The issue library: what each kind of issue is, how to fix it, CWE and OWASP.
    Library {
        /// Show one entry (an id, check or class name)
        id: Option<String>,
    },
    /// Review actions waiting for human approval.
    Approvals {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    /// Crawl and audit a site as one task; tasks stopped part way resume
    /// where they left off.
    ScanTask {
        #[command(subcommand)]
        action: ScanTaskAction,
    },
    /// Scan profiles: named sets of checks and limits.
    ScanProfile {
        #[command(subcommand)]
        action: ScanProfileAction,
    },
    /// Scans that start on their own (run while `proxymind ui` or the desktop app is open).
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
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
        #[arg(long, conflicts_with = "app")]
        truth: Option<PathBuf>,
        /// Built-in ground truth: vulnshop, vampi, juice-shop or crapi
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// The model-free baseline: look for hidden files and an API description
    /// (imported, GET examples sent), check every access-control candidate
    /// as the other identities and prove each leak, then sweep the recorded
    /// GET operations with the active scanner.
    Auto {
        /// Skip content discovery
        #[arg(long)]
        no_discover: bool,
        /// Skip the active-scanner sweep
        #[arg(long)]
        no_scan: bool,
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
enum PluginAction {
    /// Install the plugin in a directory (it must contain proxymind-plugin.yaml).
    /// Plugins run as you, with your permissions: install only code you trust.
    Add { dir: PathBuf },
    /// List installed plugins and what the sandbox can do on this machine.
    List,
    /// Uninstall a plugin by name.
    Remove { name: String },
    /// Turn a plugin on (installed plugins start on).
    Enable { name: String },
    /// Turn a plugin off without uninstalling it.
    Disable { name: String },
    /// Run an active-check plugin on a recorded exchange (its requests go
    /// through the policy gate).
    Check {
        name: String,
        /// The recorded exchange to check.
        #[arg(long)]
        exchange: i64,
        /// Send the plugin's requests as this identity.
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Encrypt the project (-p) into a .pmlock file to store or hand over.
    /// The passphrase comes from PROXYMIND_PASSPHRASE or a prompt.
    Lock {
        /// Output file (default: the project's name with .pmlock)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Delete the unencrypted project afterwards (a normal delete, not a secure wipe)
        #[arg(long)]
        remove: bool,
    },
    /// Decrypt a .pmlock file back into a project.
    Unlock {
        file: PathBuf,
        /// Output project (default: the file's name with .pmproj); never overwritten
        #[arg(long)]
        out: Option<PathBuf>,
    },
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
    /// Prove reflected XSS: send a request carrying a payload, then render the recorded response in
    /// headless Chromium (offline, every other request blocked) and check that the script ran.
    Xss {
        /// Target as scheme://host[:port] (or use --exchange to take it from a recorded exchange)
        #[arg(long, required_unless_present = "exchange")]
        url: Option<String>,
        #[arg(long)]
        exchange: Option<i64>,
        /// File with the raw request; put {{xss_url}} (percent-encoded), {{xss}} or {{token}} where the payload goes
        #[arg(long)]
        raw_file: PathBuf,
        /// Send with this identity's credentials
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        finding: Option<i64>,
    },
    /// Show which Chromium/Chrome XSS proofs will use (set PROXYMIND_CHROMIUM to choose one).
    Browser,
    /// Show a proof.
    Show { id: i64 },
    /// Run a proof again with the same inputs (e.g. during a retest).
    Rerun { id: i64 },
}

#[derive(Subcommand)]
enum ScanTaskAction {
    /// Crawl from a URL, then scan its origin's operations; shows progress until done.
    Run {
        url: String,
        /// light, default, thorough, api-only or a saved profile
        #[arg(long)]
        profile: Option<String>,
        /// Comma-separated checks (default: the profile's)
        #[arg(long, value_delimiter = ',')]
        checks: Vec<String>,
        #[arg(long)]
        no_crawl: bool,
        #[arg(long)]
        identity: Option<String>,
    },
    /// Continue a paused, cancelled, failed or interrupted task.
    Resume { id: String },
    /// Recent tasks.
    List,
    /// A task's progress and issues.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ScanProfileAction {
    List,
    /// Save a profile from a JSON file (name, description, checks, approval_checks,
    /// crawl, max_pages, browser, max_targets, max_requests).
    Save {
        file: PathBuf,
    },
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum ScheduleAction {
    List,
    /// Add a schedule. Times are UTC.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        identity: Option<String>,
        /// Every hour
        #[arg(long, conflicts_with_all = ["daily", "weekly"])]
        hourly: bool,
        /// Every day at HH:MM (UTC)
        #[arg(long, conflicts_with = "weekly")]
        daily: Option<String>,
        /// Every week, e.g. mon@02:30 (UTC)
        #[arg(long)]
        weekly: Option<String>,
    },
    /// Start a schedule's scan now (in this process; shows progress).
    Run {
        id: i64,
    },
    Enable {
        id: i64,
    },
    Disable {
        id: i64,
    },
    Delete {
        id: i64,
    },
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
    /// Print the newest exchange id: note it before logging in through the proxy.
    Mark,
    /// Build a login recipe from what the browser sent after `--from` (a mark):
    /// the steps the logged-in session needs, with CSRF tokens and the like
    /// read fresh on each run.
    RecordLogin {
        name: String,
        #[arg(long)]
        from: i64,
        /// Last exchange of the recording (default: the newest)
        #[arg(long)]
        to: Option<i64>,
        #[arg(long, default_value = "user")]
        role: String,
    },
    /// Learn how the app answers when the session is gone (needs a health check).
    LearnLoggedOut {
        name: String,
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
enum AssistantAction {
    /// Show the settings and whether they can be used.
    Show,
    /// Change the settings (options not given stay as they are).
    Set {
        /// anthropic, or openai (also Ollama, LM Studio, vLLM)
        #[arg(long)]
        provider: Option<String>,
        /// e.g. http://127.0.0.1:11434/v1 or https://api.anthropic.com/v1
        #[arg(long)]
        base_url: Option<String>,
        #[arg(long)]
        model: Option<String>,
        /// NAME of the environment variable holding the API key ("" for none)
        #[arg(long)]
        key_env: Option<String>,
        #[arg(long)]
        max_steps: Option<u32>,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Ask a question; the assistant may look at traffic and use tools.
    Ask {
        text: String,
        /// Continue this chat instead of starting a new one
        #[arg(long)]
        chat: Option<i64>,
    },
}

#[derive(Subcommand)]
enum NetworkAction {
    /// Print the saved settings (password hidden).
    Show,
    /// Replace the settings with a YAML or JSON file (see examples/network.yaml).
    Set {
        file: PathBuf,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Connect directly, with no client certificates.
    Clear {
        #[arg(long = "as")]
        actor: Option<String>,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    /// Print the saved rules (JSON).
    Show,
    /// Replace the rules with a YAML or JSON list; a running proxy picks them up within seconds.
    Load {
        file: PathBuf,
        /// Who is changing them: human:<name> (default: your user name)
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Remove all rules.
    Clear {
        #[arg(long = "as")]
        actor: Option<String>,
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
    /// Check that no audit record was changed, removed or reordered. Prints
    /// the head hash: note it (e.g. in the report) and pass it to --anchor
    /// later to also detect records cut off the end.
    Verify {
        /// A head hash printed by an earlier verify (a prefix of 12+ hex digits).
        #[arg(long)]
        anchor: Option<String>,
    },
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

use pm_service::ROE_SETTING;

/// Opens the project's service with its saved ROE, or saves `roe_file` first.
fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Shows a scan task's progress until it stops. Stopping this process
/// leaves the task resumable (`proxymind scan-task resume <id>`).
async fn follow_scan_task(service: &Service, me: &Actor, id: &str) -> Result<()> {
    eprintln!("task {id} (Ctrl-C stops it; `proxymind scan-task resume {id}` continues)");
    let mut last = String::new();
    loop {
        let v = service.scan_task_status(me, id)?;
        let line = format!(
            "{:?}: {} pages, {}/{} operations, {} requests, {} issues{}",
            v.status,
            v.pages_crawled,
            v.targets_done,
            v.targets_total,
            v.requests,
            v.issues.len(),
            v.current.as_deref().map(|c| format!(" · {c}")).unwrap_or_default()
        );
        if line != last {
            eprintln!("{line}");
            last = line;
        }
        if !v.status.running() {
            print_scan_task(&v)?;
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

fn print_scan_task(v: &pm_service::ScanTaskView) -> Result<()> {
    out!(
        "{} {:?}: {} pages crawled, {}/{} operations, {} requests{}",
        v.task_id,
        v.status,
        v.pages_crawled,
        v.targets_done,
        v.targets_total,
        v.requests,
        if v.relogins > 0 { format!(", {} re-login(s)", v.relogins) } else { String::new() }
    );
    for i in &v.issues {
        out!(
            "  [{}] {} at {} ({}) #{}{}",
            i.severity,
            i.title,
            i.operation,
            i.point,
            i.exchange_id,
            i.finding_id.map(|f| format!(" finding {f}")).unwrap_or_default()
        );
    }
    for n in &v.notes {
        out!("  - {n}");
    }
    if let Some(e) = &v.error {
        out!("  error: {e}");
    }
    Ok(())
}

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

fn main() -> std::process::ExitCode {
    // `run` is one large async state machine covering every command. Keep it
    // on the heap and drive it from a thread with a roomy stack: Windows
    // gives the main thread only 1 MB, which a debug build overflows.
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().thread_stack_size(8 << 20).build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: could not start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let result = std::thread::Builder::new()
        .name("proxymind-main".into())
        .stack_size(16 << 20)
        .spawn(move || rt.block_on(Box::pin(run())))
        .map_err(anyhow::Error::from)
        .and_then(|h| h.join().unwrap_or_else(|_| Err(anyhow::anyhow!("the main thread panicked"))));
    match result {
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
        Command::Proxy { listen, verify_upstream, no_http2 } => {
            let ca = Arc::new(CertAuthority::load_or_create(&home_dir(&cli)?)?);
            let store = Store::open(&cli.project)?;
            let (recorder, writer) = Recorder::spawn(store);
            // In-scope-only rules need the rules of engagement; without
            // them only rules marked "any host" apply.
            let rewriter = Arc::new(pm_proxy::Rewriter::new());
            match open_service(&cli.project, None) {
                Ok(service) => {
                    let service = Arc::new(service);
                    service.attach_rewriter(rewriter.clone())?;
                    service.attach_recorder(&recorder)?;
                    pm_service::watch_roe(service);
                }
                Err(_) => eprintln!("No rules of engagement: in-scope-only match-and-replace rules are off."),
            }
            let network = pm_service::pm_replay::Network::new();
            let hooks = pm_proxy::Hooks {
                rewrite: Some(rewriter.clone()),
                network: Some(network.clone()),
                http2: !*no_http2,
                ..Default::default()
            };
            let proxy = Proxy::with_hooks(ca.clone(), recorder, *verify_upstream, hooks)?;
            let extra = pm_proxy::Listeners::new(proxy.clone(), Some(*listen));
            pm_service::watch_project(&cli.project, Some(rewriter), network, Some(extra))?;
            let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding {listen}"))?;
            pm_proxy::listeners::warn_if_exposed(*listen);
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
        Command::Search { query, regex, case_sensitive, part, invert, in_scope, host, limit, json } => {
            let service = open_service(&cli.project, None)?;
            let r = service.history_search_text(
                &human_actor(None)?,
                &pm_service::SearchRequest {
                    query: query.clone(),
                    regex: *regex,
                    case_sensitive: *case_sensitive,
                    part: Some(part.clone()),
                    invert: *invert,
                    max_scan: Some(pm_service::MAX_SCAN),
                    filter: pm_store::HistoryFilter {
                        host: host.clone(),
                        limit: Some(*limit),
                        in_scope: in_scope.then_some(true),
                        ..Default::default()
                    },
                },
            )?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for h in &r.hits {
                    let e = &h.exchange;
                    out!("#{} {} {}{} [{}, {} match(es)]", e.id, e.method, e.host, e.path, h.part, h.matches);
                    for s in &h.snippets {
                        out!("    {}", s.text);
                    }
                }
                out!("{} hit(s) in {} exchange(s)", r.hits.len(), r.scanned);
            }
        }
        Command::Sitemap { host, json } => {
            let service = open_service(&cli.project, None)?;
            let sites = service.site_map(&human_actor(None)?, host.as_deref())?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&sites)?);
            } else {
                fn walk(n: &pm_service::pm_tools::sitemap::Node, depth: usize) -> anyhow::Result<()> {
                    for c in &n.children {
                        let statuses: Vec<String> = c.statuses.iter().map(u16::to_string).collect();
                        let here = if c.requests > 0 {
                            format!("  {} {} ({})", c.methods.join(","), statuses.join(","), c.requests)
                        } else {
                            String::new()
                        };
                        out!("{}{}{}", "  ".repeat(depth), c.name, here);
                        walk(c, depth + 1)?;
                    }
                    Ok(())
                }
                for s in &sites {
                    out!("{} ({} requests{})", s.site.origin, s.site.total, if s.in_scope { ", in scope" } else { "" });
                    walk(&s.site.root, 1)?;
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
        Command::Assistant { action: AssistantAction::Show } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            let cfg = service.assistant_config()?;
            out!("{}", serde_json::to_string_pretty(&cfg)?);
            let local = pm_assistant::is_local_url(&cfg.base_url);
            out!("Model server: {}", if local { "local" } else { "cloud" });
            match pm_assistant::Assistant::new(service)?.check(&cfg) {
                Ok(_) => out!("✓ ready"),
                Err(e) => out!("✗ {e}"),
            }
        }
        Command::Assistant {
            action: AssistantAction::Set { provider, base_url, model, key_env, max_steps, actor },
        } => {
            let service = open_service(&cli.project, None)?;
            let mut cfg = service.assistant_config()?;
            if let Some(p) = provider {
                cfg.provider = serde_json::from_value(serde_json::json!(p))
                    .with_context(|| format!("unknown provider {p:?}: use anthropic or openai"))?;
            }
            if let Some(v) = base_url {
                cfg.base_url = v.clone();
            }
            if let Some(v) = model {
                cfg.model = v.clone();
            }
            if let Some(v) = key_env {
                cfg.api_key_env = v.clone();
            }
            if let Some(v) = max_steps {
                cfg.max_steps = *v;
            }
            let saved = service.assistant_config_set(&human_actor(actor.as_deref())?, cfg)?;
            out!("✓ assistant settings saved");
            out!("{}", serde_json::to_string_pretty(&saved)?);
        }
        Command::Assistant { action: AssistantAction::Ask { text, chat } } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            let assistant = pm_assistant::Assistant::new(service)?;
            let turn = assistant.send(*chat, text).await?;
            for m in &turn.messages {
                for b in &m.content {
                    match b {
                        pm_assistant::llm::Block::Text { text } if m.role == pm_assistant::llm::Role::Assistant => {
                            out!("{text}\n")
                        }
                        pm_assistant::llm::Block::ToolUse { name, input, .. } => out!("  → {name} {input}"),
                        pm_assistant::llm::Block::ToolResult { is_error: true, content, .. } => {
                            out!("  ✗ {}", content.chars().take(200).collect::<String>())
                        }
                        _ => {}
                    }
                }
            }
            if let Some(n) = turn.note {
                out!("({n})");
            }
            out!("(chat {}; continue with --chat {})", turn.chat_id, turn.chat_id);
        }
        Command::Network { action: NetworkAction::Show } => {
            let cfg = pm_service::load_network(&Store::open(&cli.project)?)?.masked();
            out!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Command::Network { action: NetworkAction::Set { file, actor } } => {
            let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
            let cfg: pm_service::pm_replay::NetConfig =
                serde_saphyr::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
            let service = open_service(&cli.project, None)?;
            let saved = service.network_set(&human_actor(actor.as_deref())?, cfg)?;
            out!("✓ network settings saved; running proxies pick them up within seconds");
            out!("{}", serde_json::to_string_pretty(&saved)?);
        }
        Command::Network { action: NetworkAction::Clear { actor } } => {
            let service = open_service(&cli.project, None)?;
            service.network_set(&human_actor(actor.as_deref())?, Default::default())?;
            out!("✓ direct connections, no client certificates");
        }
        Command::Rules { action: RulesAction::Show } => {
            let rules = pm_service::load_rules(&Store::open(&cli.project)?)?;
            out!("{}", serde_json::to_string_pretty(&rules)?);
        }
        Command::Rules { action: RulesAction::Load { file, actor } } => {
            let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
            let rules: Vec<pm_proxy::RewriteRule> =
                serde_saphyr::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
            let service = open_service(&cli.project, None)?;
            let saved = service.set_match_replace_rules(&human_actor(actor.as_deref())?, rules)?;
            out!("✓ {} match-and-replace rule(s) saved", saved.len());
        }
        Command::Rules { action: RulesAction::Clear { actor } } => {
            let service = open_service(&cli.project, None)?;
            service.set_match_replace_rules(&human_actor(actor.as_deref())?, vec![])?;
            out!("✓ match-and-replace rules cleared");
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
            attach_plugins(&cli, &service);
            if let Some(addr) = oast_listen {
                start_oast(&service, *addr, oast_public_url.clone()).await?;
            }
            pm_service::watch_project(&cli.project, None, service.network().clone(), None)?;
            pm_service::watch_roe(service.clone());
            eprintln!("ProxyMind MCP server for {} on project {}", actor.id(), cli.project.display());
            pm_mcp::McpServer::new(service, actor).serve_stdio().await?;
        }
        Command::Ui { listen, proxy, no_proxy, no_http2, actor, bind_any, open_browser } => {
            anyhow::ensure!(
                listen.ip().is_loopback() || *bind_any,
                "the UI/API must listen on a loopback address (inside a container, add --bind-any and publish the \
                 port on 127.0.0.1 only)"
            );
            let home = home_dir(&cli)?;
            let token = pm_api::load_or_create_token(&home.join("api-token"))?;
            let service = Arc::new(open_service(&cli.project, None)?);
            attach_plugins(&cli, &service);
            let me = human_actor(actor.as_deref())?;
            let mut setup = pm_api::ProxySetup::default();
            if !*no_proxy {
                let ca = Arc::new(CertAuthority::load_or_create(&home)?);
                setup = pm_api::ProxySetup { proxy: Some(proxy.to_string()), ca_pem: Some(ca.ca_pem().to_string()) };
                let (recorder, _writer) = Recorder::spawn(Store::open(&cli.project)?);
                service.attach_recorder(&recorder)?;
                let queue = Arc::new(pm_proxy::InterceptQueue::new());
                service.attach_intercept(queue.clone());
                let rewriter = Arc::new(pm_proxy::Rewriter::new());
                service.attach_rewriter(rewriter.clone())?;
                let hooks = pm_proxy::Hooks {
                    rewrite: Some(rewriter.clone()),
                    intercept: Some(queue),
                    network: Some(service.network().clone()),
                    http2: !*no_http2,
                };
                let p = Proxy::with_hooks(ca.clone(), recorder, false, hooks)?;
                let extra = pm_proxy::Listeners::new(p.clone(), Some(*proxy));
                service.attach_listeners(extra.clone())?;
                pm_service::watch_project(&cli.project, Some(rewriter), service.network().clone(), Some(extra))?;
                let l =
                    tokio::net::TcpListener::bind(proxy).await.with_context(|| format!("binding proxy on {proxy}"))?;
                pm_proxy::listeners::warn_if_exposed(*proxy);
                tokio::spawn(p.run(l));
                eprintln!("Proxy on http://{proxy} (CA: {})", ca.ca_cert_path().display());
                service.attach_proxy_info(pm_service::ProxyInfo {
                    addr: proxy.to_string(),
                    ca_pem: ca.ca_pem().to_string(),
                    profile_dir: cli.project.with_extension("browser"),
                });
                if *open_browser {
                    match service.browser_open(&me, Default::default()).await {
                        Ok(b) => eprintln!("Browser opened at {} (profile {})", b.url, b.profile),
                        Err(e) => eprintln!("Could not open the browser: {e}"),
                    }
                }
            } else {
                pm_service::watch_project(&cli.project, None, service.network().clone(), None)?;
            }
            pm_service::watch_roe(service.clone());
            // Scheduled scans start while the UI server runs.
            tokio::spawn(service.clone().run_scheduler());
            let state = pm_api::AppState::new(service, me.clone(), token.clone(), cli.project.display().to_string())?
                .with_setup(setup);
            let l = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("binding UI on {listen}"))?;
            eprintln!("ProxyMind UI for {} on project {}", me.id(), cli.project.display());
            let shown =
                if listen.ip().is_unspecified() { SocketAddr::from(([127, 0, 0, 1], listen.port())) } else { *listen };
            out!("Open: http://{shown}/auth?token={token}");
            tokio::select! {
                r = axum::serve(l, pm_api::router(state)) => r?,
                _ = tokio::signal::ctrl_c() => eprintln!("\nShutting down"),
            }
        }
        Command::OastServer { listen, public_url, dns, domain, dns_answer, smtp } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            start_oast(&service, *listen, public_url.clone()).await?;
            if let (Some(addr), Some(domain)) = (dns, domain) {
                let ip = dns_answer.unwrap_or(match listen.ip() {
                    std::net::IpAddr::V4(v4) if !v4.is_unspecified() => v4,
                    _ => std::net::Ipv4Addr::LOCALHOST,
                });
                service.set_oast_dns_domain(domain)?;
                let sock = tokio::net::UdpSocket::bind(addr).await.with_context(|| format!("binding DNS on {addr}"))?;
                let s = service.clone();
                tokio::spawn(pm_oast::dns::serve(sock, domain.to_ascii_lowercase(), ip, move |i| {
                    if let Err(e) = s.record_oast(&i) {
                        eprintln!("could not record OAST interaction: {e}");
                    }
                }));
                eprintln!("OAST DNS on {addr} for *.{domain} (A → {ip}); delegate the domain here with an NS record");
            }
            if let Some(addr) = smtp {
                let l = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding SMTP on {addr}"))?;
                service.set_oast_smtp(&l.local_addr()?.to_string())?;
                let s = service.clone();
                let host = domain.clone().unwrap_or_else(|| "proxymind-oast".into());
                tokio::spawn(pm_oast::smtp::serve(l, host, move |i| {
                    if let Err(e) = s.record_oast(&i) {
                        eprintln!("could not record OAST interaction: {e}");
                    }
                }));
                eprintln!("OAST SMTP on {addr}: mail to a payload address is recorded");
            }
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
        Command::Scan { host, min_severity, json } => {
            let service = open_service(&cli.project, None)?;
            attach_plugins(&cli, &service);
            let issues = service.scan_passive(
                &human_actor(None)?,
                &pm_service::ScanFilter { host: host.clone(), min_severity: min_severity.clone(), limit: None },
            )?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&issues)?);
            } else {
                for i in &issues {
                    out!(
                        "{:<6} {}  {}{}  ({}×, e.g. #{})\n         {}",
                        format!("{:?}", i.severity).to_lowercase(),
                        i.title,
                        i.origin,
                        if i.path == "*" { String::new() } else { i.path.clone() },
                        i.count,
                        i.exchange_ids.first().copied().unwrap_or_default(),
                        i.evidence
                    );
                }
                out!("{} issues (leads to test, not findings)", issues.len());
            }
        }
        Command::Project { action } => project_command(&cli.project, action)?,
        Command::Plugin { action } => {
            let home = home_dir(&cli)?;
            let mut reg = pm_plugin::Registry::load(&home)?;
            match action {
                PluginAction::Add { dir } => {
                    let p = reg.add(dir)?.clone();
                    reg.save()?;
                    out!("✓ installed {} {} from {}", p.manifest.name, p.manifest.version, p.dir.display());
                    if p.manifest.passive.is_some() {
                        out!("  Passive: runs with the passive scan (`proxymind scan`, the Issues page).");
                    }
                    if p.manifest.active.is_some() {
                        out!("  Active: run it on a recorded request (`proxymind plugin check`, the Plugins page).");
                    }
                    out!("  Sandbox: {}. Install only code you trust.", pm_plugin::sandbox::status().summary);
                }
                PluginAction::List => {
                    if reg.plugins.is_empty() {
                        out!("No plugins installed. See examples/plugins/.");
                    }
                    for p in &reg.plugins {
                        out!(
                            "{:<20} {:<8} {:<15} {:<3} {}  ({})",
                            p.manifest.name,
                            p.manifest.version,
                            p.manifest.kinds().join("+"),
                            if p.enabled { "on" } else { "off" },
                            p.manifest.description,
                            p.dir.display()
                        );
                    }
                    out!("Sandbox: {}", pm_plugin::sandbox::status().summary);
                }
                PluginAction::Enable { name } | PluginAction::Disable { name } => {
                    let on = matches!(action, PluginAction::Enable { .. });
                    anyhow::ensure!(reg.set_enabled(name, on), "no plugin named {name}");
                    reg.save()?;
                    out!("✓ {name} is {}", if on { "on" } else { "off" });
                }
                PluginAction::Check { name, exchange, identity, json } => {
                    let service = open_service(&cli.project, None)?;
                    service.attach_plugin_home(home.clone());
                    let req = pm_service::PluginCheckRequest {
                        plugin: name.clone(),
                        exchange_id: *exchange,
                        identity: identity.clone(),
                        approval_id: None,
                    };
                    let r = service.plugin_check(&human_actor(None)?, req).await?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&r)?);
                    } else {
                        match r {
                            pm_service::PluginCheckResult::Done { issues, exchange_ids, notes } => {
                                out!("Sent {} request(s): exchanges {:?}", exchange_ids.len(), exchange_ids);
                                for i in &issues {
                                    out!(
                                        "  [{}] {} — {} (exchange {})",
                                        i.severity,
                                        i.title,
                                        i.evidence,
                                        i.exchange_id
                                    );
                                }
                                if issues.is_empty() {
                                    out!("  no issues");
                                }
                                for n in notes {
                                    out!("  note: {n}");
                                }
                            }
                            pm_service::PluginCheckResult::Denied { reasons } => {
                                anyhow::bail!("denied: {}", reasons.join("; "))
                            }
                            pm_service::PluginCheckResult::PendingApproval { summary, .. } => {
                                out!("Needs approval: {summary}")
                            }
                        }
                    }
                }
                PluginAction::Remove { name } => {
                    anyhow::ensure!(reg.remove(name), "no plugin named {name}");
                    reg.save()?;
                    out!("✓ removed {name}");
                }
            }
        }
        Command::ScanActive { exchange_id, checks, identity, json } => {
            let service = open_service(&cli.project, None)?;
            let r = service
                .scan_active(
                    &human_actor(None)?,
                    pm_service::ActiveScanRequest {
                        exchange_id: *exchange_id,
                        checks: checks.clone(),
                        identity: identity.clone(),
                        ..Default::default()
                    },
                )
                .await?;
            match (&r, *json) {
                (pm_service::ActiveScanResult::Done { requests, issues, insertion_points, .. }, false) => {
                    out!(
                        "{} insertion point(s), {requests} probe(s), {} lead(s)",
                        insertion_points.len(),
                        issues.len()
                    );
                    for f in issues {
                        out!(
                            "{:<6} {}  [{} = {}]  #{}",
                            f.issue.severity,
                            f.issue.title,
                            f.issue.point,
                            f.issue.payload,
                            f.exchange_id
                        );
                        out!("         {}", f.issue.evidence);
                        if let Some(p) = &f.issue.prove_with {
                            out!("         prove: {p}");
                        }
                    }
                }
                _ => out!("{}", serde_json::to_string_pretty(&r)?),
            }
        }
        Command::Openapi { file, exchange, base_url, send, identity, json } => {
            let service = open_service(&cli.project, None)?;
            let spec = match file {
                Some(f) => Some(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?),
                None => None,
            };
            anyhow::ensure!(spec.is_some() || exchange.is_some(), "give a spec file or --exchange");
            let r = service
                .openapi_import(
                    &human_actor(None)?,
                    pm_service::OpenApiImportRequest {
                        spec,
                        exchange_id: *exchange,
                        base_url: base_url.clone(),
                        send_examples: *send,
                        identity: identity.clone(),
                        approval_id: None,
                    },
                )
                .await?;
            match (&r, *json) {
                (
                    pm_service::OpenApiImportResult::Imported {
                        title,
                        version,
                        base_url,
                        operations,
                        sent,
                        skipped,
                        ..
                    },
                    false,
                ) => {
                    out!(
                        "{title} {version} ({}): {} operations",
                        base_url.as_deref().unwrap_or("no base URL"),
                        operations.len()
                    );
                    for o in operations {
                        out!("  {:<7} {}{}  {}", o.method, o.path, if o.auth { "  🔒" } else { "" }, o.summary);
                    }
                    for x in sent {
                        out!(
                            "  sent {} {} → {} (#{})",
                            x.method,
                            x.path,
                            x.status.map_or("err".into(), |s| s.to_string()),
                            x.exchange_id
                        );
                    }
                    for x in skipped {
                        out!("  skipped {x}");
                    }
                }
                _ => out!("{}", serde_json::to_string_pretty(&r)?),
            }
        }
        Command::Graphql { url, schema, exchange, fetch, identity, examples, json } => {
            let service = open_service(&cli.project, None)?;
            let schema = match schema {
                Some(f) => Some(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?),
                None => None,
            };
            anyhow::ensure!(
                schema.is_some() || exchange.is_some() || *fetch,
                "give --schema, --exchange or --fetch (with --url)"
            );
            let r = service
                .graphql_import(
                    &human_actor(None)?,
                    pm_service::GraphQlImportRequest {
                        url: url.clone(),
                        schema,
                        exchange_id: *exchange,
                        fetch: *fetch,
                        identity: identity.clone(),
                        approval_id: None,
                    },
                )
                .await?;
            match (&r, *json) {
                (pm_service::GraphQlImportResult::Imported { url, types, operations, truncated, .. }, false) => {
                    out!(
                        "{}: {} operations, {types} types{}",
                        url.as_deref().unwrap_or("(no endpoint given)"),
                        operations.len(),
                        if *truncated > 0 { format!(" ({truncated} more not listed)") } else { String::new() }
                    );
                    for o in operations {
                        let args: Vec<String> = o.op.args.iter().map(|a| format!("{}: {}", a.name, a.ty)).collect();
                        out!("  {:<12} {}({}): {}", o.op.kind, o.op.name, args.join(", "), o.op.returns);
                        if *examples && let Some(req) = &o.example_request {
                            out!("{}\n", req.replace("\r\n", "\n"));
                        }
                    }
                }
                _ => out!("{}", serde_json::to_string_pretty(&r)?),
            }
        }
        Command::Import { file } => {
            let service = open_service(&cli.project, None)?;
            let har = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
            let r = service.traffic_import_har(&human_actor(None)?, &pm_service::ImportRequest { har })?;
            out!("Imported {} exchanges.", r.imported);
            for s in &r.skipped {
                out!("  skipped: {s}");
            }
        }
        Command::Export { out, ids, host, limit } => {
            let service = open_service(&cli.project, None)?;
            let req = pm_service::ExportRequest {
                ids: (!ids.is_empty()).then(|| ids.clone()),
                filter: pm_store::HistoryFilter { host: host.clone(), limit: *limit, ..Default::default() },
            };
            let har = service.traffic_export_har(&human_actor(None)?, &req)?;
            let n = har["log"]["entries"].as_array().map_or(0, Vec::len);
            match out {
                Some(path) => {
                    std::fs::write(path, har.to_string()).with_context(|| format!("writing {}", path.display()))?;
                    eprintln!("Wrote {n} exchanges to {}", path.display());
                }
                None => out!("{har}"),
            }
        }
        Command::Curl { exchange_id, parse } => match (exchange_id, parse) {
            (_, Some(cmd)) => {
                let cmd = if cmd == "-" {
                    let mut s = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                    s
                } else {
                    cmd.clone()
                };
                let c = pm_service::pm_tools::curl::parse_curl(&cmd).map_err(|e| anyhow::anyhow!(e))?;
                for w in &c.warnings {
                    eprintln!("warning: {w}");
                }
                eprintln!("# send to {}://{}", c.url.scheme, c.url.authority());
                out!("{}", String::from_utf8_lossy(&c.raw));
            }
            (Some(id), None) => {
                let service = open_service(&cli.project, None)?;
                out!("{}", service.exchange_curl(&human_actor(None)?, *id)?);
            }
            (None, None) => anyhow::bail!("give an exchange id or --parse"),
        },
        Command::Decode { input, ops } => {
            // Local only: no project needed.
            let steps = if ops.is_empty() {
                pm_service::pm_tools::codec::smart_decode(input)
            } else {
                pm_service::pm_tools::codec::chain(ops, input)?
            };
            let r = serde_json::json!({ "steps": steps });
            for step in r["steps"].as_array().into_iter().flatten() {
                out!("[{}]\n{}\n", step["op"].as_str().unwrap_or(""), step["output"].as_str().unwrap_or(""));
            }
            if r["steps"].as_array().is_none_or(|a| a.is_empty()) {
                out!("nothing to decode");
            }
        }
        Command::Compare { a, b } => {
            let service = open_service(&cli.project, None)?;
            let r = service.compare_exchanges(&human_actor(None)?, *a, *b)?;
            if let Some(s) = r["response_semantic"]["summary"].as_str() {
                out!("Responses: {s}");
            }
            for part in ["request_lines", "response_lines"] {
                out!("\n== {} (+{} -{})", part.replace('_', " "), r[part]["added"], r[part]["removed"]);
                for l in r[part]["lines"].as_array().into_iter().flatten() {
                    let sign = match l["op"].as_str() {
                        Some("added") => "+",
                        Some("removed") => "-",
                        _ => " ",
                    };
                    if sign != " " {
                        out!("{sign} {}", l["text"].as_str().unwrap_or(""));
                    }
                }
            }
        }
        Command::TokenAnalyzer { exchange_id, locator, samples, identity } => {
            let service = open_service(&cli.project, None)?;
            let r = service
                .token_analyzer_run(
                    &human_actor(None)?,
                    pm_service::TokenAnalyzerRequest {
                        exchange_id: *exchange_id,
                        locator: locator.clone(),
                        samples: Some(*samples),
                        identity: identity.clone(),
                        approval_id: None,
                    },
                )
                .await?;
            out!("{}", serde_json::to_string_pretty(&r)?);
        }
        Command::Discover { url, wordlist, builtin, extensions, max_requests, identity, json } => {
            let service = open_service(&cli.project, None)?;
            let words = match wordlist {
                Some(f) => std::fs::read_to_string(f)
                    .with_context(|| format!("reading {}", f.display()))?
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect(),
                None => Vec::new(),
            };
            let r = service
                .discover(
                    &human_actor(None)?,
                    pm_service::DiscoverRequest {
                        url: url.clone(),
                        words,
                        builtin: *builtin,
                        extensions: extensions.clone(),
                        max_requests: Some(*max_requests),
                        identity: identity.clone(),
                        approval_id: None,
                    },
                )
                .await?;
            match (&r, *json) {
                (pm_service::DiscoverResult::Done { base, tried, found, soft_404, skipped, errors }, false) => {
                    for f in found {
                        let note = f.note.map(|n| format!("  ({n})")).unwrap_or_default();
                        let loc = f.location.as_deref().map(|l| format!(" → {l}")).unwrap_or_default();
                        out!("{:>5}  {:>8}  #{:<6} {}{loc}{note}", f.status, f.length, f.exchange_id, f.url);
                    }
                    out!(
                        "\n{} found in {tried} requests under {base}{}",
                        found.len(),
                        if *soft_404 { " (the server answers missing pages with a soft 404; filtered)" } else { "" }
                    );
                    for s in skipped.iter().take(20) {
                        out!("  skipped {s}");
                    }
                    for e in errors {
                        out!("  error {e}");
                    }
                }
                _ => out!("{}", serde_json::to_string_pretty(&r)?),
            }
        }
        Command::Crawl { url, max_pages, max_depth, no_robots, identity, browser, json } => {
            let service = open_service(&cli.project, None)?;
            let r = service
                .crawl(
                    &human_actor(None)?,
                    pm_service::CrawlRequest {
                        url: url.clone(),
                        max_pages: Some(*max_pages),
                        max_depth: Some(*max_depth),
                        robots: Some(!*no_robots),
                        identity: identity.clone(),
                        approval_id: None,
                        browser: Some(*browser),
                    },
                )
                .await?;
            match (&r, *json) {
                (
                    pm_service::CrawlResult::Done {
                        pages, forms, skipped, skipped_total, not_visited, not_sent, ..
                    },
                    false,
                ) => {
                    for p in pages {
                        out!(
                            "{:>5}  #{:<6} {}",
                            p.status.map_or("err".into(), |s| s.to_string()),
                            p.exchange_id,
                            p.url
                        );
                    }
                    out!(
                        "\n{} pages, {} forms, {skipped_total} links skipped, {not_visited} not visited",
                        pages.len(),
                        forms.len()
                    );
                    for f in forms {
                        out!("  form {} {} ({})", f.method, f.action, f.inputs.join(", "));
                    }
                    for s in skipped.iter().take(20) {
                        out!("  skipped {}: {}", s.url, s.reason);
                    }
                    for n in not_sent.iter().take(20) {
                        out!("  not sent (would change state): {n}");
                    }
                }
                _ => out!("{}", serde_json::to_string_pretty(&r)?),
            }
        }
        Command::Fuzzer {
            url,
            exchange,
            raw_file,
            mode,
            payload_files,
            numbers,
            builtin,
            url_encode,
            grep,
            identity,
            json,
        } => {
            let service = open_service(&cli.project, None)?;
            let mode: pm_service::pm_fuzz::Mode = serde_json::from_value(serde_json::json!(mode)).map_err(|_| {
                anyhow::anyhow!("mode must be one_at_a_time, same_everywhere, paired or all_combinations")
            })?;
            let set =
                |list: Vec<String>, numbers: Option<String>, builtin: Option<String>| pm_service::pm_fuzz::PayloadSet {
                    list,
                    numbers,
                    builtin,
                    url_encode: *url_encode,
                    ..Default::default()
                };
            let mut sets = Vec::new();
            for f in payload_files {
                let text = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
                sets.push(set(text.lines().filter(|l| !l.is_empty()).map(str::to_string).collect(), None, None));
            }
            if numbers.is_some() || builtin.is_some() {
                sets.push(set(vec![], numbers.clone(), builtin.clone()));
            }
            anyhow::ensure!(!sets.is_empty(), "give payloads with --payloads, --numbers or --builtin");
            let r = service
                .fuzzer_run(
                    &human_actor(None)?,
                    pm_service::FuzzerRequest {
                        url: url.clone(),
                        exchange_id: *exchange,
                        raw: std::fs::read_to_string(raw_file)?,
                        mode,
                        payload_sets: sets,
                        grep: grep.clone(),
                        identity: identity.clone(),
                        ..Default::default()
                    },
                )
                .await?;
            match (&r, *json) {
                (pm_service::FuzzerResult::Done { baseline, results, anomalies, note }, false) => {
                    if let Some(n) = note {
                        out!("note: {n}");
                    }
                    let line = |label: &str, r: &pm_service::FuzzerRow| -> Result<()> {
                        out!(
                            "{label:>5}  #{:<6} {:>5}  {:>7} B  {:>6} ms  {}{}",
                            r.exchange_id,
                            r.status.map_or("err".into(), |s| s.to_string()),
                            r.body_length,
                            r.elapsed_ms,
                            r.payloads.iter().map(|p| p.as_deref().unwrap_or("·")).collect::<Vec<_>>().join(" | "),
                            if r.matches.is_empty() {
                                String::new()
                            } else {
                                format!("  grep: {}", r.matches.join(", "))
                            }
                        );
                        Ok(())
                    };
                    line("base", baseline)?;
                    for (i, row) in results.iter().enumerate() {
                        line(&(i + 1).to_string(), row)?;
                    }
                    out!("\n{} anomalies:", anomalies.len());
                    for a in anomalies {
                        out!("  {}: {}", a.index + 1, a.reasons.join("; "));
                    }
                }
                _ => out!("{}", serde_json::to_string_pretty(&r)?),
            }
        }
        Command::Proof { action: ProofAction::Browser } => match pm_service::pm_browser::find_chromium() {
            Some(p) => out!("browser for XSS proofs: {}", p.display()),
            None => out!(
                "no Chromium or Chrome found; install one or set {} to its path",
                pm_service::pm_browser::ENV_CHROMIUM
            ),
        },
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
                ProofAction::Xss { url, exchange, raw_file, identity, finding } => {
                    let raw = std::fs::read_to_string(raw_file)?;
                    let r = service
                        .proof_run(
                            &human_actor(None)?,
                            pm_service::ProofRequest {
                                oracle: "reflection".into(),
                                url: url.clone(),
                                exchange_id: *exchange,
                                raw: Some(raw),
                                identity: identity.clone(),
                                finding_id: *finding,
                                ..Default::default()
                            },
                        )
                        .await?;
                    print_result(&r)?;
                }
                ProofAction::Browser => unreachable!("handled above"),
                ProofAction::Show { id } => out!("{}", serde_json::to_string_pretty(&service.proof_get(*id)?)?),
                ProofAction::Rerun { id } => {
                    let r = service.proof_rerun(&human_actor(None)?, *id).await?;
                    out!("{}", serde_json::to_string_pretty(&r)?);
                }
            }
        }
        Command::Bench { action: BenchAction::Auto { no_discover, no_scan, json } } => {
            let service = open_service(&cli.project, None)?;
            let me = human_actor(None)?;
            let disc = if *no_discover { None } else { Some(service.auto_discover(&me).await?) };
            let r = service.auto_access_control(&me).await?;
            let sweep = if *no_scan { None } else { Some(service.auto_active_sweep(&me).await?) };
            if *json {
                out!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "discover": disc, "access_control": r, "scan": sweep })
                    )?
                );
            } else {
                if let Some(d) = &disc {
                    out!("discovery: {} found on {} origin(s)", d.found, d.origins.len());
                    for l in &d.leads {
                        out!("  ? suspected exposure {} (finding #{})", l.operation, l.finding_id);
                    }
                    if let Some((url, ops, sent)) = &d.openapi {
                        out!("  API description {url}: {ops} operations, {sent} GET examples sent");
                    }
                    for s in d.skipped.iter().take(10) {
                        out!("  skipped {s}");
                    }
                }
                out!("{} candidates, {} checked, {} leaks", r.candidates, r.checks, r.leaks);
                for l in &r.exposures {
                    out!("  ? suspected exposure {}: {} (finding #{})", l.operation, l.evidence, l.finding_id);
                }
                for p in &r.results {
                    out!(
                        "  {} {}: {} reads {}'s data (finding #{})",
                        if p.proven { "✓ proven" } else { "✗ not proven" },
                        p.operation,
                        p.attacker,
                        p.owner,
                        p.finding_id
                    );
                }
                if let Some(sw) = &sweep {
                    out!(
                        "active sweep: {} operations, {} requests, {} leads",
                        sw.operations,
                        sw.requests,
                        sw.leads.len()
                    );
                    for l in &sw.leads {
                        out!("  ? suspected {} {} (finding #{})", l.check, l.operation, l.finding_id);
                    }
                    for s in sw.skipped.iter().take(10) {
                        out!("  skipped {s}");
                    }
                }
            }
        }
        Command::Bench { action: BenchAction::Score { truth, app, json } } => {
            let service = open_service(&cli.project, None)?;
            let truth = match app {
                Some(a) => bench::builtin_truth(a)?,
                None => bench::load_truth(truth.as_deref())?,
            };
            // The method comes from each finding's first evidence exchange, so a
            // GET finding never matches a DELETE endpoint with the same path.
            let mut findings = service.finding_list(None)?;
            for f in &mut findings {
                let first = f["evidence"].as_array().and_then(|e| e.first()).and_then(serde_json::Value::as_i64);
                if let Some(ex) = first.and_then(|id| service.exchange_raw(id).ok()) {
                    f["method"] = serde_json::json!(ex.summary.method);
                }
            }
            let score = bench::score(&truth, &findings);
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
        Command::Report { out: file, format, template, min_severity, no_evidence } => {
            let service = open_service(&cli.project, None)?;
            let from_ext =
                file.as_ref().and_then(|f| f.extension()).and_then(|e| e.to_str()).map(str::to_ascii_lowercase);
            let fmt = match format.as_deref().or(from_ext.as_deref()).unwrap_or("md") {
                "htm" => "html",
                "markdown" => "md",
                f => f,
            };
            let opts = pm_service::ReportOptions {
                min_severity: min_severity.clone(),
                evidence: no_evidence.then_some(false),
                ..Default::default()
            };
            let r = service.report_render(template.as_deref(), fmt, &opts).await?;
            match file {
                Some(f) => {
                    std::fs::write(f, &r.body)?;
                    out!("✓ report written to {}", f.display());
                }
                None if fmt == "pdf" => anyhow::bail!("a PDF report needs --out <file.pdf>"),
                None => out!("{}", String::from_utf8_lossy(&r.body)),
            }
        }
        Command::Library { id } => match id {
            Some(id) => {
                let i =
                    pm_service::pm_scan::library::lookup(id).with_context(|| format!("no library entry for {id}"))?;
                out!("{} ({}) · typical severity {}", i.name, i.id, i.severity);
                let cwe: Vec<String> = i.cwe.iter().map(|n| format!("CWE-{n}")).collect();
                out!("{} · {}{}", cwe.join(", "), i.owasp, i.owasp_api.map(|a| format!(" · {a}")).unwrap_or_default());
                out!("\nWhat it is: {}\n\nImpact: {}\n\nFix: {}", i.background, i.impact, i.remediation);
                for r in i.references {
                    out!("  {r}");
                }
            }
            None => {
                for i in pm_service::pm_scan::library::LIBRARY {
                    out!("{:<22} {:<8} {}", i.id, i.severity, i.name);
                }
            }
        },
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
        Command::ScanTask { action } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            let me = human_actor(None)?;
            match action {
                ScanTaskAction::Run { url, profile, checks, no_crawl, identity } => {
                    let req = pm_service::ScanTaskRequest {
                        url: url.clone(),
                        profile: profile.clone(),
                        checks: checks.clone(),
                        crawl: no_crawl.then_some(false),
                        identity: identity.clone(),
                        ..Default::default()
                    };
                    let v = service.scan_task_start(&me, req)?;
                    follow_scan_task(&service, &me, &v.task_id).await?;
                }
                ScanTaskAction::Resume { id } => {
                    service.scan_task_resume(&me, id)?;
                    follow_scan_task(&service, &me, id).await?;
                }
                ScanTaskAction::List => {
                    let list = service.scan_task_list(&me);
                    if list.is_empty() {
                        out!("No scan tasks yet. Start one with `proxymind scan-task run <url>`.");
                    }
                    for v in list {
                        out!(
                            "{}  {:<9} {}/{} operations  {} requests  {}{}",
                            v.task_id,
                            format!("{:?}", v.status).to_lowercase(),
                            v.targets_done,
                            v.targets_total,
                            v.requests,
                            v.url,
                            v.profile.map(|p| format!("  [{p}]")).unwrap_or_default()
                        );
                    }
                }
                ScanTaskAction::Show { id, json } => {
                    let v = service.scan_task_status(&me, id)?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&v)?);
                    } else {
                        print_scan_task(&v)?;
                    }
                }
            }
        }
        Command::ScanProfile { action } => {
            let service = open_service(&cli.project, None)?;
            let me = human_actor(None)?;
            match action {
                ScanProfileAction::List => {
                    for p in service.scan_profiles()? {
                        let checks = if p.checks.is_empty() {
                            if p.approval_checks { "all checks".to_string() } else { "all safe checks".to_string() }
                        } else {
                            p.checks.join(",")
                        };
                        out!("{:<10} {}{}", p.name, if p.builtin { "(built-in) " } else { "" }, p.description);
                        out!("           checks: {checks}");
                    }
                }
                ScanProfileAction::Save { file } => {
                    let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
                    let p: pm_service::ScanProfile = serde_json::from_str(&text)?;
                    let name = p.name.clone();
                    service.scan_profile_save(&me, p)?;
                    out!("saved profile {name}");
                }
                ScanProfileAction::Delete { name } => {
                    let d = service.scan_profile_delete(&me, name)?;
                    out!("{}", if d { format!("deleted {name}") } else { format!("no saved profile {name}") });
                }
            }
        }
        Command::Schedule { action } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            let me = human_actor(None)?;
            match action {
                ScheduleAction::List => {
                    let list = service.schedule_list()?;
                    if list.is_empty() {
                        out!("No schedules. Add one with `proxymind schedule add --name … --url … --daily 02:00`.");
                    }
                    for s in list {
                        let every = match &s.every {
                            pm_service::Every::Hourly => "hourly".to_string(),
                            pm_service::Every::Daily { at } => format!("daily {at} UTC"),
                            pm_service::Every::Weekly { day, at } => format!("weekly {day} {at} UTC"),
                        };
                        out!(
                            "#{:<3} {:<8} {:<24} {} {}  next in {} min{}",
                            s.id,
                            if s.enabled { "on" } else { "off" },
                            s.name,
                            every,
                            s.request.url,
                            ((s.next_run_ms - now_ms()) / 60_000).max(0),
                            s.last_error.map(|e| format!("  (last: {e})")).unwrap_or_default()
                        );
                    }
                }
                ScheduleAction::Add { name, url, profile, identity, hourly, daily, weekly } => {
                    let every = match (hourly, daily, weekly) {
                        (true, _, _) => pm_service::Every::Hourly,
                        (_, Some(at), _) => pm_service::Every::Daily { at: at.clone() },
                        (_, _, Some(w)) => {
                            let (day, at) = w.split_once('@').context("--weekly takes day@HH:MM, e.g. mon@02:30")?;
                            pm_service::Every::Weekly { day: day.into(), at: at.into() }
                        }
                        _ => anyhow::bail!("say when: --hourly, --daily HH:MM or --weekly day@HH:MM"),
                    };
                    let s = service.schedule_save(
                        &me,
                        pm_service::ScanSchedule {
                            name: name.clone(),
                            every,
                            request: pm_service::ScanTaskRequest {
                                url: url.clone(),
                                profile: profile.clone(),
                                identity: identity.clone(),
                                ..Default::default()
                            },
                            enabled: true,
                            ..Default::default()
                        },
                    )?;
                    out!(
                        "schedule #{} saved; next run in {} min (runs while `proxymind ui` or the desktop app is open)",
                        s.id,
                        (s.next_run_ms - now_ms()) / 60_000
                    );
                }
                ScheduleAction::Run { id } => {
                    let v = service.schedule_run_now(&me, *id)?;
                    follow_scan_task(&service, &me, &v.task_id).await?;
                }
                ScheduleAction::Enable { id } | ScheduleAction::Disable { id } => {
                    let mut s = service
                        .schedule_list()?
                        .into_iter()
                        .find(|s| s.id == *id)
                        .with_context(|| format!("no schedule #{id}"))?;
                    s.enabled = matches!(action, ScheduleAction::Enable { .. });
                    service.schedule_save(&me, s)?;
                    out!(
                        "schedule #{id} {}",
                        if matches!(action, ScheduleAction::Enable { .. }) { "on" } else { "off" }
                    );
                }
                ScheduleAction::Delete { id } => {
                    let d = service.schedule_delete(&me, *id)?;
                    out!("{}", if d { format!("deleted #{id}") } else { format!("no schedule #{id}") });
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
                IdentityAction::Mark => out!("{}", service.history_mark()?),
                IdentityAction::RecordLogin { name, from, to, role } => {
                    let r = service.identity_record_login(&me, name, role, *from, *to)?;
                    out!("recorded a {}-step login for {}:", r.steps.len(), r.name);
                    for st in &r.steps {
                        let mut extra = String::new();
                        if !st.uses.is_empty() {
                            extra.push_str(&format!(" uses {}", st.uses.join(",")));
                        }
                        if !st.extracts.is_empty() {
                            extra.push_str(&format!(" reads {}", st.extracts.join(",")));
                        }
                        out!("  #{} {} {}{extra}", st.exchange_id, st.method, st.url);
                    }
                    out!("  session: cookies=[{}] headers=[{}]", r.cookies.join(","), r.headers.join(","));
                    for n in &r.notes {
                        out!("  - {n}");
                    }
                }
                IdentityAction::LearnLoggedOut { name } => {
                    let l = service.identity_learn_logged_out(&me, name).await?;
                    let lo = &l.logged_out;
                    if !lo.statuses.is_empty() {
                        out!("{name}: logged out when the status is {:?}", lo.statuses);
                    }
                    if !lo.location_contains.is_empty() {
                        out!("{name}: logged out when redirected to {}", lo.location_contains);
                    }
                    if !lo.body_contains.is_empty() {
                        out!("{name}: logged out when the page says {:?}", lo.body_contains);
                    }
                    if lo == &Default::default() {
                        out!("{name}: the usual signs (401, redirect to a login page) are enough");
                    }
                    if let Some(c) = &l.health_contains {
                        out!("{name}: health check now also needs {c:?}");
                    }
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
        Command::Audit { action: AuditAction::Verify { anchor } } => {
            let store = Store::open(&cli.project)?;
            let n = pm_service::verify_audit(&store)?;
            let records = store.audit_records()?;
            let hex = |h: &[u8]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
            if let Some(a) = anchor {
                let a = a.trim().to_ascii_lowercase();
                anyhow::ensure!(a.len() >= 12 && a.chars().all(|c| c.is_ascii_hexdigit()), "give 12+ hex digits");
                let Some(at) = records.iter().position(|r| hex(&r.hash).starts_with(&a)) else {
                    anyhow::bail!("anchor {a} is not in the audit log: records were removed from the end");
                };
                out!("✓ anchor found at record {} of {n}", at + 1);
            }
            let head = records.last().map(|r| hex(&r.hash)).unwrap_or_default();
            out!("✓ audit log intact: {n} records, chain verified (head {})", &head[..head.len().min(24)]);
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

fn is_locked(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 8];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut head)).is_ok() && pm_vault::is_sealed(&head)
}

fn passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("PROXYMIND_PASSPHRASE") {
        return Ok(p);
    }
    let p = rpassword::prompt_password("Passphrase: ")?;
    if confirm {
        anyhow::ensure!(rpassword::prompt_password("Repeat it: ")? == p, "the passphrases don't match");
    }
    Ok(p)
}

/// A sibling path that doesn't exist yet, for writing before a rename.
fn temp_beside(path: &std::path::Path, tag: &str) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.{tag}-{}-{}", std::process::id(), jiff::Timestamp::now().as_millisecond()))
}

fn project_command(project: &std::path::Path, action: &ProjectAction) -> Result<()> {
    match action {
        ProjectAction::Lock { out, remove } => {
            anyhow::ensure!(project.exists(), "{} does not exist", project.display());
            anyhow::ensure!(!is_locked(project), "{} is already locked", project.display());
            let out = out.clone().unwrap_or_else(|| project.with_extension("pmlock"));
            anyhow::ensure!(!out.exists(), "{} already exists", out.display());
            let pass = passphrase(true)?;
            // A consistent single-file copy first (the live file may have a WAL).
            let snap = temp_beside(project, "snapshot");
            Store::open(project)?.snapshot_to(&snap)?;
            let tmp = temp_beside(&out, "partial");
            let sealed = (|| -> Result<u64> {
                let mut input = std::io::BufReader::new(std::fs::File::open(&snap)?);
                let mut output = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
                Ok(pm_vault::seal(&mut input, &mut output, &pass, pm_vault::Cost::default())?)
            })();
            let _ = std::fs::remove_file(&snap);
            let bytes = match sealed {
                Ok(n) => n,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            };
            std::fs::rename(&tmp, &out)?;
            out!("✓ locked {} ({bytes} bytes) into {}", project.display(), out.display());
            if *remove {
                for suffix in ["", "-wal", "-shm"] {
                    let p = PathBuf::from(format!("{}{suffix}", project.display()));
                    if p.exists() {
                        std::fs::remove_file(&p)?;
                    }
                }
                out!(
                    "  removed the unencrypted project (a normal delete; use full-disk encryption for stronger guarantees)"
                );
            }
        }
        ProjectAction::Unlock { file, out } => {
            anyhow::ensure!(is_locked(file), "{} is not a locked project", file.display());
            let out = out.clone().unwrap_or_else(|| file.with_extension("pmproj"));
            anyhow::ensure!(!out.exists(), "{} already exists; choose another --out", out.display());
            let pass = passphrase(false)?;
            let tmp = temp_beside(&out, "partial");
            let opened = (|| -> Result<u64> {
                let mut input = std::io::BufReader::new(std::fs::File::open(file)?);
                let mut output = std::io::BufWriter::new(pm_store::create_private(&tmp)?);
                Ok(pm_vault::open(&mut input, &mut output, &pass)?)
            })();
            match opened {
                Ok(n) => {
                    std::fs::rename(&tmp, &out)?;
                    out!("✓ unlocked {} ({n} bytes) into {}", file.display(), out.display());
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

/// Points the service at the user's plugin registry (read when used, so
/// changes apply without a restart); problems are reported, not fatal.
fn attach_plugins(cli: &Cli, service: &pm_service::Service) {
    match home_dir(cli) {
        Ok(h) => service.attach_plugin_home(h),
        Err(e) => eprintln!("plugins not loaded: {e}"),
    }
}
