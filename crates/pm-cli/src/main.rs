//! `proxymind`: command-line entry point.

mod bench;
mod remote;
mod token_cmd;

use std::net::{IpAddr, SocketAddr};
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
    /// AI scan: the configured model assesses the target on its own, recon to chained proofs (see `assistant`).
    AiScan {
        #[command(subcommand)]
        action: AiScanAction,
    },
    /// Export a signed evidence pack (report, exact traffic, proofs, audit chain, scope, coverage) for the client.
    Evidence {
        /// Where to write the ZIP.
        #[arg(long, default_value = "proxymind-evidence.zip")]
        out: PathBuf,
        /// Also include the bytes of every in-scope exchange (up to 5000), not only the evidence.
        #[arg(long)]
        all: bool,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Scan a staging URL in a pipeline: scope file, crawl, scan, prove, SARIF/JUnit/JSON, fail on new findings.
    Ci(CiArgs),
    /// Proven findings as regression tests for CI: export them, or run them against a test environment.
    Regress {
        #[command(subcommand)]
        action: RegressAction,
    },
    /// What changed since the last test: save model snapshots and compare with one, or with an older project.
    Changes {
        /// Save the current model as a snapshot with this name (e.g. at the end of a test).
        #[arg(long)]
        save: Option<String>,
        /// Compare with this snapshot (name or id; default: the newest).
        #[arg(long)]
        snapshot: Option<String>,
        /// Compare with another project file instead (e.g. last year's engagement).
        #[arg(long)]
        since: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Check an evidence pack: signature, file hashes, audit chain, scope, evidence. Needs no project.
    Verify {
        pack: PathBuf,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Passive recon that sends nothing to the target: DNS records, Wayback Machine history.
    Recon {
        #[command(subcommand)]
        action: ReconAction,
    },
    /// Saved workflows: chains of match, extract, transform, send and assert steps (built in the UI's Workflows page).
    Workflow {
        #[command(subcommand)]
        action: WorkflowAction,
    },
    /// Integrations: Jira, GitHub, GitLab, Slack and webhooks (set up on the Integrations page; tokens never go in the project).
    Integration {
        #[command(subcommand)]
        action: IntegrationAction,
    },
    /// Testing playbooks for agents and people (also MCP prompts): list, or print one.
    Skills {
        /// A skill to print; none lists them.
        name: Option<String>,
        /// What to concentrate on, filled into the skill.
        #[arg(long)]
        focus: Option<String>,
    },
    /// Check for a newer ProxyMind release (off unless you turn it on or ask).
    Update {
        #[command(subcommand)]
        action: UpdateAction,
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
    /// Make, list and revoke `pm3_` tokens for agents, CI jobs and plugins (ADR-0022).
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Save a project server's address, certificate pin and your token, and check them by asking who you are.
    Login {
        /// The server's address, e.g. https://pm.example.com:7777
        url: String,
        /// Pin a self-signed certificate: sha256:<base64 or hex of its public key>, as the server printed at start.
        /// Without it the certificate must verify against the public roots.
        #[arg(long)]
        pin: Option<String>,
        /// Read the token from this environment variable (else it is asked for, hidden, or read from stdin).
        #[arg(long)]
        token_env: Option<String>,
    },
    /// Forget a server saved by `proxymind login` (its address, pin and token).
    Logout {
        /// The server's address, as given to `login`
        url: String,
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
        /// Do not run tools here: bridge stdin/stdout to this project server's MCP endpoint
        /// (https://host[:port]), as the agent your `pm3_` token is. The pin and token saved by `proxymind login`
        /// are used unless given.
        #[arg(long)]
        server: Option<String>,
        /// With --server: read the token from this environment variable (default: the one saved by `login`).
        #[arg(long)]
        token_env: Option<String>,
        /// With --server: pin a self-signed certificate (default: the pin saved by `login`).
        #[arg(long)]
        pin: Option<String>,
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
    /// Run the project server: the web UI and API for several people with accounts, over TLS (ADR-0022; see
    /// docs/server-mode.md). The first start prints a one-time setup URL.
    Serve {
        /// Turn on accounts: sessions instead of the install token. Required (this is what `serve` is for).
        #[arg(long)]
        accounts: bool,
        /// Where the accounts live (server.db, server.key and the self-signed certificate). Default: <home>/server
        #[arg(long, env = "PROXYMIND_SERVER_HOME")]
        server_home: Option<PathBuf>,
        /// Where the UI and API listen. Anything but loopback needs TLS (or --behind-proxy).
        #[arg(long, default_value = "127.0.0.1:7777")]
        listen: SocketAddr,
        /// The address people type, e.g. https://pm.example.com. Browsers must send an Origin that matches it.
        /// Required beyond loopback and behind a proxy.
        #[arg(long)]
        public_url: Option<String>,
        /// Another Host name to answer to (repeatable).
        #[arg(long = "allowed-host")]
        allowed_host: Vec<String>,
        /// Your own TLS certificate chain (PEM); re-read when the file changes.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// The private key for --tls-cert (PEM).
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// A self-signed certificate kept in the server home; its key pin is printed for clients.
        #[arg(long)]
        tls_self_signed: bool,
        /// A reverse proxy terminates TLS in front of this server (which then listens on loopback or a private address).
        #[arg(long)]
        behind_proxy: bool,
        /// The reverse proxy's address (repeatable); X-Forwarded-* are believed only from it.
        #[arg(long = "trusted-proxy")]
        trusted_proxy: Vec<IpAddr>,
        /// Also run the interception proxy here. Off by default: the interception CA's key should stay on the
        /// tester's machine, not on a shared server.
        #[arg(long)]
        proxy: Option<SocketAddr>,
        /// Speak only HTTP/1.1 to proxy clients (HTTP/2 is offered by default).
        #[arg(long)]
        no_http2: bool,
    },
    /// Administer a project server from its own host.
    Server {
        #[command(subcommand)]
        action: ServerAction,
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
    /// What has and hasn't been tested: every operation × vulnerability class, with who tested it and how.
    Coverage {
        /// Include tested and vulnerable cells, not only open and untested ones
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
        /// Run this workflow (name or id) on each result
        #[arg(long)]
        workflow: Option<String>,
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

/// Exit codes of `proxymind ci`, shown by `--help`.
const CI_HELP: &str = "\
EXIT CODES:
  0  The run finished and found no new finding at or above --fail-on and --min-severity.
  1  The run found new findings that fail it (not in the baseline, severe enough, proven or, with
     --fail-on suspected, also suspected). This wins over 2.
  2  The run could not finish properly, so it says nothing about the target: the ROE is invalid or does not
     allow the target, the target is unreachable, a login failed, the request or time budget ran out before
     the scan finished, the rules of engagement skipped checks or operations (unless --allow-skipped), nothing
     was found to scan, or an input or output file could not be read or written.

CI acts as the actor ci:pipeline. Nobody can approve anything in a pipeline, so what the ROE leaves at
\"approve\" for CI is skipped and reported, never granted. CI's section in the ROE is tiers.ci; without it CI
may send safe (GET) requests only, so scanning needs `tiers: {ci: {active_intrusive: allow}}`.

A fresh in-memory project is used unless --project is given. Even then, listeners, schedules and workflow
triggers in the project file are not started, and its network settings, session rules and OAST settings are
ignored. The target's TLS certificate is verified unless --insecure is given.

Credentials: identity files may name environment variables as ${NAME}; the values never appear in output.
See docs/ci.md.";

#[derive(clap::Args)]
#[command(after_long_help = CI_HELP)]
struct CiArgs {
    /// Rules of engagement (required): the scope, the time windows and what CI may do (tiers.ci).
    #[arg(long, value_name = "ROE.YAML")]
    roe: PathBuf,
    /// The URL to test (must be in scope; default: the first scope entry without a wildcard).
    #[arg(long)]
    target: Option<String>,
    /// Known findings (from --write-baseline): only findings not in it fail the run.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Write this run's proven findings (with --baseline-suspected, also suspected ones) as a baseline.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,
    /// With --write-baseline: include suspected findings.
    #[arg(long)]
    baseline_suspected: bool,
    /// Write SARIF 2.1.0 here (fingerprints and baseline states included).
    #[arg(long, value_name = "FILE")]
    sarif: Option<PathBuf>,
    /// Write JUnit XML here: a test case per finding and per step of the run.
    #[arg(long, value_name = "FILE")]
    junit: Option<PathBuf>,
    /// Write the JSON summary here.
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
    /// What a new finding must be to fail the run.
    #[arg(long, value_parser = ["proven", "suspected", "none"], default_value = "proven")]
    fail_on: String,
    /// Ignore findings below this severity.
    #[arg(long, value_parser = ["info", "low", "medium", "high", "critical"], default_value = "low")]
    min_severity: String,
    /// light, default, thorough, api-only (see `proxymind scan-profile list`).
    #[arg(long, default_value = "default")]
    profile: String,
    /// Stop after this many minutes (a hard cap: the run then exits 2).
    #[arg(long, value_name = "N")]
    budget_minutes: Option<u64>,
    /// Send at most this many requests to the target (a hard cap: the run then exits 2).
    #[arg(long, value_name = "N")]
    max_requests: Option<u64>,
    /// Identity to log in and scan as; repeat for more (the first scans, all are used for access-control checks).
    #[arg(long = "identity", value_name = "NAME")]
    identities: Vec<String>,
    /// JSON file defining identities (auth, health check, login recipe); ${ENV_VAR} in values is filled in.
    #[arg(long = "identity-file", value_name = "FILE")]
    identity_files: Vec<PathBuf>,
    /// An OpenAPI or Swagger description to import (its GET examples are sent).
    #[arg(long, value_name = "FILE")]
    openapi: Option<PathBuf>,
    /// Do not verify the target's TLS certificate (staging hosts with self-signed certificates).
    #[arg(long)]
    insecure: bool,
    /// Crawl without a headless browser (links and forms only).
    #[arg(long)]
    no_browser: bool,
    /// Accept a run where the rules skipped some checks, or nothing was found to scan (still reported).
    #[arg(long)]
    allow_skipped: bool,
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
        /// Skip the automatic prove step (pick an oracle per suspected finding and prove it)
        #[arg(long)]
        no_prove: bool,
        /// Also run the write checks last: the API description's write operations on a
        /// test user's object, as the owner (ReDoS) and as another user (authorization).
        /// They change data and can slow the server; destructive tier (approval).
        #[arg(long)]
        write_checks: bool,
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
    /// Try to prove a finding (an id), or every suspected finding, with the
    /// oracle that fits its class; proven ones get a stored proof.
    Prove { id: Option<i64> },
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
    Add {
        dir: PathBuf,
        /// Refuse plugins that aren't signed by a key on your trusted list
        #[arg(long)]
        require_signed: bool,
    },
    /// List installed plugins and what the sandbox can do on this machine.
    List,
    /// Make a signing key for plugins you publish (keep the file private).
    Keygen {
        /// Where to write the private key (PKCS#8)
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign the plugin in a directory (writes proxymind-plugin.sig).
    Sign {
        dir: PathBuf,
        /// Private key from `plugin keygen`
        #[arg(long)]
        key: PathBuf,
        /// Your name, shown with the signature
        #[arg(long)]
        signer: String,
    },
    /// Trust a signer's public key (hex, from `plugin keygen`).
    Trust {
        key: String,
        #[arg(long)]
        name: String,
    },
    /// Stop trusting a key.
    Untrust { key: String },
    /// List trusted signer keys.
    Trusted,
    /// Uninstall a plugin by name.
    Remove { name: String },
    /// Accept the permissions a version 2 plugin declares (and turn it on). Needed after installing one, and
    /// again when an update changes its permissions.
    Accept { name: String },
    /// Turn a plugin on (installed plugins start on; version 2 plugins need `accept` first).
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
    /// Show whether this installation trusts the project (-p) and what safe mode holds back.
    Status {
        /// Print the full review as JSON
        #[arg(long)]
        json: bool,
    },
    /// Review the project (-p) and trust it: its listeners, schedules, workflow triggers, upstream and rewrite
    /// rules and rules of engagement then take effect, and run as you. A project made by this installation is
    /// trusted already; one that came from somewhere else opens in safe mode until you do this.
    Trust {
        /// Do not ask; trust what is shown (for scripts that have already reviewed it)
        #[arg(long)]
        yes: bool,
        /// Act as this person (default: human:$USER)
        #[arg(long)]
        actor: Option<String>,
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
    /// Every readable operation as every identity: a role x endpoint grid with flagged cells.
    Matrix {
        /// Prove each flagged cell and record proven ones as findings.
        #[arg(long)]
        prove: bool,
        /// Most operations to test (default 40).
        #[arg(long)]
        max: Option<usize>,
        #[arg(long)]
        json: bool,
        #[arg(long = "actor")]
        actor: Option<String>,
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
enum AiScanAction {
    /// Start a scan and follow it until it ends (Ctrl+C leaves it running only in this process: stop it first).
    Start {
        /// Target URL (default: the first URL in the scope).
        #[arg(long)]
        target: Option<String>,
        /// What to concentrate on.
        #[arg(long)]
        focus: Option<String>,
        /// Most model calls (default 150).
        #[arg(long)]
        max_steps: Option<u32>,
        /// Longest run in minutes (default 60).
        #[arg(long)]
        minutes: Option<u32>,
        /// Most to spend in USD (needs prices in the assistant settings).
        #[arg(long)]
        max_cost: Option<f64>,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// List scans, or show one with its log.
    Status { id: Option<i64> },
    /// Print a scan's report (or write it to a file).
    Report {
        id: i64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Ask a running scan to stop (works from another terminal).
    Stop {
        id: i64,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Send a running scan a message ("focus on checkout", "why did you try that?"); it gets it on its next step.
    Say {
        id: i64,
        text: String,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Print the attack paths a scan recorded (all scans' without an id).
    Paths { id: Option<i64> },
    /// Print what agents remembered about hosts (all hosts without one).
    Memory { host: Option<String> },
    /// Print the system prompt a scan would use.
    Prompt,
}

#[derive(Subcommand)]
enum RegressAction {
    /// Write a test per proven finding (plus a README and an example CI workflow) to a ZIP.
    Export {
        #[arg(long, default_value = "proxymind-regressions.zip")]
        out: PathBuf,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// Run tests (files or directories of *.json) and say which findings are still there. Needs no project.
    /// Credentials come from PM_AUTH_<IDENTITY> environment variables. Exits 1 if any finding is still there, or
    /// if a test can't tell (credentials not accepted, the server failing): that is an error, never "fixed".
    /// Exits 2 if a test was skipped (a credential variable is not set), unless --allow-skipped.
    Run {
        paths: Vec<PathBuf>,
        /// Send to this origin instead of the one each test was recorded on, e.g. https://staging.example.com.
        #[arg(long)]
        target: Option<String>,
        /// Write JUnit XML here for the CI dashboard.
        #[arg(long)]
        junit: Option<PathBuf>,
        /// Accept the target's TLS certificate without checking it (self-signed test environments).
        #[arg(long)]
        insecure: bool,
        /// Print the results as JSON.
        #[arg(long)]
        json: bool,
        /// Let tests whose credential variable is not set be skipped without failing the run (local runs).
        /// In CI a missing secret would otherwise pass silently.
        #[arg(long)]
        allow_skipped: bool,
    },
}

#[derive(Subcommand)]
enum ReconAction {
    /// DNS records of a host in scope (or a parent domain), with notes (SPF, DMARC, CAA, dangling CNAMEs).
    Dns {
        host: String,
        /// Resolver to ask, e.g. 1.1.1.1:53 (default: the system's).
        #[arg(long)]
        resolver: Option<std::net::SocketAddr>,
        #[arg(long = "as")]
        actor: Option<String>,
    },
    /// URLs the Internet Archive captured for a host in scope, interesting ones first.
    Wayback {
        host: String,
        /// Most URLs to print (default 100).
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long = "as")]
        actor: Option<String>,
    },
}

#[derive(Subcommand)]
enum IntegrationAction {
    /// The project's integrations: kind, whether each is on, what needs review, the last error.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Check one integration (reads the tracker's project, posts a test message or a `test` event) and log it.
    /// Exits 1 unless it worked.
    Test {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Create the finding's issue in a Jira, GitHub or GitLab integration (text and requests are redacted). A finding
    /// that already has one there is refused unless --update.
    SendFinding {
        /// The finding's id.
        finding: i64,
        /// The integration's name.
        integration: String,
        /// Update the existing issue instead of refusing.
        #[arg(long)]
        update: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum WorkflowAction {
    /// The project's workflows: name, steps, whether the per-exchange trigger is on.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Run a workflow by name or id. Every send goes through the rules of engagement as you; a send that needs an
    /// approval pauses the run (continue with --approval once it is approved). Exits 1 unless the run is ok.
    Run {
        /// The workflow's name or id.
        workflow: String,
        /// Start on this recorded exchange (needed unless the first step sends a request of its own).
        #[arg(long)]
        exchange: Option<i64>,
        /// Continue a run that waits for this approval (give the same --exchange).
        #[arg(long)]
        approval: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long = "as")]
        actor: Option<String>,
    },
}

/// Where `proxymind token` works: the install's own file, or a server home.
#[derive(clap::Args)]
struct TokenTarget {
    /// On the server host: the server home that holds server.db and server.key. Without it, the tokens are this
    /// install's (single-user mode, `<home>/tokens.json`).
    #[arg(long)]
    server_home: Option<PathBuf>,
    /// With --server-home: the account the token belongs to.
    #[arg(long)]
    user: Option<String>,
    /// With --server-home: the project's id (default: read from the project file).
    #[arg(long)]
    project_id: Option<String>,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Make a token. It is printed once, on stdout alone; keep it where only the agent or job can read it.
    Create {
        /// What it acts as
        #[arg(long, value_parser = ["agent", "ci", "plugin"])]
        kind: String,
        /// The actor name: agent:<name>, ci:<name> or plugin:<name> in the audit log
        #[arg(long)]
        name: String,
        /// The role ceiling (never owner); the token acts with the lower of this and its owner's role
        #[arg(long, default_value = "tester", value_parser = ["tester", "viewer"])]
        role: String,
        /// The highest tier it may reach: read, passive, active_safe, active_intrusive (the rules can narrow it more)
        #[arg(long)]
        tier_cap: Option<String>,
        /// Lifetime: 30d, 12h or 90m (at most 365d)
        #[arg(long, default_value = "30d")]
        expires: String,
        #[command(flatten)]
        target: TokenTarget,
    },
    /// List tokens (never their secrets).
    List {
        #[arg(long)]
        json: bool,
        /// With --server-home: everyone's tokens in the project, not only --user's
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        target: TokenTarget,
    },
    /// Revoke a token: it stops working at its next request.
    Revoke {
        /// The token's id (t_…), as `token list` shows it
        id: String,
        #[command(flatten)]
        target: TokenTarget,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Lost every owner? Ends all sessions and prints a new one-time setup URL that creates a new owner (the
    /// authority needed is write access to the server home).
    ResetOwner {
        /// The server home that holds server.db and server.key. Default: <home>/server
        #[arg(long, env = "PROXYMIND_SERVER_HOME")]
        server_home: Option<PathBuf>,
        /// The server's public address, to print the full URL (default: a placeholder you complete).
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Ask GitHub now whether a newer release is out (one GET of the public releases list).
    Check,
    /// Show the setting and the last answer (sends nothing).
    Status,
    /// Let the UI check once a day.
    On,
    /// Stop the daily check.
    Off,
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
        /// A signed checkpoint file (from `audit checkpoint -o`) to check the log against; repeatable. Detects
        /// records cut off the end and a log rewritten before the checkpoint.
        #[arg(long)]
        checkpoint: Vec<PathBuf>,
        /// Only accept checkpoints signed by the key with this fingerprint (from `audit checkpoint`'s output).
        #[arg(long)]
        checkpoint_key: Option<String>,
        /// File holding the audit key (64 hex digits, or raw bytes) of a keyed (server) log: checks every record's MAC.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Fail unless the log is keyed (use with --key-file for a server project).
        #[arg(long)]
        require_keyed: bool,
    },
    /// Write a signed checkpoint of the audit log (head hash, record count, time). Keep the file somewhere the
    /// project file's writers cannot reach; `audit verify --checkpoint` then detects truncation and rewriting.
    Checkpoint {
        /// Write the checkpoint to this file (JSON); without it, print it.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Who is asking (people only).
        #[arg(long)]
        actor: Option<String>,
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

/// Identity definitions from JSON files (one object or a list per file), with `${NAME}` in string values filled in
/// from the environment. Returns the identities and every credential value, so nothing prints them.
fn load_identity_files(paths: &[PathBuf]) -> Result<(Vec<pm_service::pm_identity::Identity>, Vec<String>)> {
    fn expand(v: &mut serde_json::Value, secrets: &mut Vec<String>) -> Result<(), String> {
        match v {
            serde_json::Value::String(s) => {
                *s = pm_service::pm_tools::ci::expand_env(s, &|k| std::env::var(k).ok(), secrets)?;
                Ok(())
            }
            serde_json::Value::Array(a) => a.iter_mut().try_for_each(|x| expand(x, secrets)),
            serde_json::Value::Object(o) => o.values_mut().try_for_each(|x| expand(x, secrets)),
            _ => Ok(()),
        }
    }
    let (mut identities, mut secrets) = (Vec::new(), Vec::new());
    for path in paths {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("{} is not valid JSON", path.display()))?;
        let items = match value {
            serde_json::Value::Array(a) => a,
            one => vec![one],
        };
        for mut item in items {
            expand(&mut item, &mut secrets).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            let ident: pm_service::pm_identity::Identity = serde_json::from_value(item).map_err(|e| {
                // serde's messages can quote the offending value, which may be a credential.
                let mut msg = e.to_string();
                for secret in &secrets {
                    msg = msg.replace(secret.as_str(), "[redacted]");
                }
                anyhow::anyhow!("{}: not a valid identity definition: {msg}", path.display())
            })?;
            for (_, v) in ident.auth.cookies.iter().chain(&ident.auth.headers) {
                if !v.is_empty() {
                    secrets.push(v.clone());
                }
            }
            identities.push(ident);
        }
    }
    Ok((identities, secrets))
}

/// `proxymind ci`. Returns the exit code (see `CI_HELP`); an `Err` is a run that could not start, which is exit 2 too.
async fn run_ci(cli: &Cli, project_given: bool, a: &CiArgs) -> Result<i32> {
    use pm_service::pm_tools::ci::{Baseline, FailOn, Gate};
    let roe_text = std::fs::read_to_string(&a.roe).with_context(|| format!("reading {}", a.roe.display()))?;
    let roe = Roe::parse(&roe_text).with_context(|| format!("the rules of engagement in {}", a.roe.display()))?;
    let target = match &a.target {
        Some(t) => t.clone(),
        None => roe
            .include
            .iter()
            .map(|p| p.text.clone())
            .find(|t| !t.contains('*'))
            .context("no --target given and the ROE's scope has no entry without a wildcard to use")?,
    };
    let baseline = match &a.baseline {
        Some(path) => {
            let text = std::fs::read_to_string(path).with_context(|| {
                format!("reading the baseline {} (create one with --write-baseline on a first run)", path.display())
            })?;
            let b = Baseline::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            Some((path.display().to_string(), b))
        }
        None => None,
    };
    let (identity_defs, secrets) = load_identity_files(&a.identity_files)?;
    let openapi = match &a.openapi {
        Some(path) => Some(std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?),
        None => None,
    };
    let store = if project_given {
        anyhow::ensure!(
            !is_locked(&cli.project),
            "{} is sealed; `proxymind project unlock` it first",
            cli.project.display()
        );
        Store::open(&cli.project)?
    } else {
        Store::open_in_memory()?
    };
    let sender = pm_service::pm_replay::Sender::new(!a.insecure)?
        .with_timeouts(std::time::Duration::from_secs(15), std::time::Duration::from_secs(60));
    let service = Arc::new(Service::with_sender(store, Policy::new(roe), sender)?);

    let tool = format!("ProxyMind {}", env!("CARGO_PKG_VERSION"));
    eprintln!("{tool}: CI run against {target} as ci:pipeline, profile {}", a.profile);
    if a.insecure {
        eprintln!("  WARNING: TLS verification is OFF (--insecure): the target's certificate is not checked");
    } else {
        eprintln!("  TLS verification of the target: on");
    }
    if project_given {
        eprintln!(
            "  project {}: listeners, schedules and workflow triggers in it are not started; its network settings, \
             session rules and OAST settings are ignored",
            cli.project.display()
        );
    } else {
        eprintln!("  project: fresh and in memory, discarded afterwards");
    }
    let opts = pm_service::CiOptions {
        target,
        profile: a.profile.clone(),
        actor_name: "pipeline".into(),
        max_requests: a.max_requests,
        budget_minutes: a.budget_minutes,
        identity_defs,
        use_identities: a.identities.clone(),
        secrets,
        openapi,
        browser: !a.no_browser,
        baseline,
        gate: Gate {
            fail_on: FailOn::parse(&a.fail_on).context("--fail-on is proven, suspected or none")?,
            min_severity: a.min_severity.clone(),
        },
        allow_skipped: a.allow_skipped,
        tls_verified: !a.insecure,
        tool: tool.clone(),
    };
    let progress = |m: &str| eprintln!("  {m}");
    let mut run = service.ci_run(&opts, &progress).await?;

    if let Some(path) = &a.write_baseline {
        if run.summary.complete {
            let b = Baseline::from_findings(
                &run.summary.findings,
                a.baseline_suspected,
                &run.summary.target,
                &tool,
                &jiff::Timestamp::now().to_string(),
            );
            std::fs::write(path, b.to_json()).with_context(|| format!("writing {}", path.display()))?;
            run.summary.baseline_written = Some(path.display().to_string());
        } else {
            eprintln!("  baseline NOT written: the run did not finish, so it would record a partial picture");
        }
    }
    if let Some(path) = &a.sarif {
        std::fs::write(path, serde_json::to_string_pretty(&run.sarif)? + "\n")
            .with_context(|| format!("writing {}", path.display()))?;
    }
    if let Some(path) = &a.junit {
        std::fs::write(path, run.summary.junit()).with_context(|| format!("writing {}", path.display()))?;
    }
    if let Some(path) = &a.json {
        std::fs::write(path, run.summary.json()).with_context(|| format!("writing {}", path.display()))?;
    }
    out!("{}", run.summary.text().trim_end());
    Ok(run.summary.exit_code)
}

/// The user's home folder for this run, set once at start (the trust records live there, F-2).
static HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The server home: the flag, else `<home>/server`.
/// `proxymind token create | list | revoke`.
fn token_command(cli: &Cli, action: &TokenAction) -> Result<()> {
    let target = match action {
        TokenAction::Create { target, .. } | TokenAction::List { target, .. } | TokenAction::Revoke { target, .. } => {
            target
        }
    };
    let need_user = matches!(action, TokenAction::Create { .. });
    let store = match &target.server_home {
        Some(dir) => token_cmd::open_server(
            &token_cmd::ServerArgs {
                server_home: dir,
                user: target.user.as_deref(),
                project_id: target.project_id.as_deref(),
                project_file: &cli.project,
            },
            need_user,
        )?,
        None => {
            anyhow::ensure!(
                target.user.is_none() && target.project_id.is_none(),
                "--user and --project-id are for a server's tokens: add --server-home on the server host"
            );
            token_cmd::open_home(&home_dir(cli)?)?
        }
    };
    match action {
        TokenAction::Create { kind, name, role, tier_cap, expires, .. } => {
            let made = store.create(&token_cmd::spec(kind, name, role, tier_cap.as_deref(), expires)?)?;
            eprintln!("Token created: {}", token_cmd::describe(&made.info));
            eprintln!("It is shown once and cannot be shown again: store it where only the {kind} can read it.");
            eprintln!("Use it as `Authorization: Bearer <token>`, or `proxymind login` / `proxymind mcp --server`.");
            out!("{}", made.token.expose());
        }
        TokenAction::List { json, all, .. } => {
            let list = store.list(*all)?;
            if *json {
                let rows: Vec<serde_json::Value> = list
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "id": t.id, "kind": t.kind.as_str(), "name": t.name, "actor": t.actor_id(),
                            "owner": t.user_id, "project_id": t.project_id, "role": t.role.as_str(),
                            "tier_cap": t.tier_cap, "created_at": t.created_at, "expires_at": t.expires_at,
                            "last_used_at": t.last_used_at, "use_count": t.use_count, "revoked_at": t.revoked_at,
                        })
                    })
                    .collect();
                out!("{}", serde_json::to_string_pretty(&rows)?);
            } else if list.is_empty() {
                out!("No tokens. Make one with `proxymind token create --kind agent --name claude`.");
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
                    .unwrap_or(0);
                out!("{}", token_cmd::table(&list, now).trim_end());
            }
        }
        TokenAction::Revoke { id, .. } => {
            store.revoke(id)?;
            out!("Revoked {id}. It stops working at its next request.");
        }
    }
    Ok(())
}

fn server_home_dir(cli: &Cli, given: Option<&std::path::Path>) -> Result<PathBuf> {
    Ok(match given {
        Some(d) => d.to_path_buf(),
        None => home_dir(cli)?.join("server"),
    })
}

fn private_dir(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// `proxymind server reset-owner`: ends every session and returns the URL of a fresh one-time setup. The token is in
/// the URL's fragment (`#setup=`), which a browser never sends to a server or writes to a log.
fn reset_owner(home: &std::path::Path, public_url: Option<&str>) -> Result<String> {
    anyhow::ensure!(
        home.join("server.db").exists() && home.join("server.key").exists(),
        "no server.db and server.key in {}: this is not a server home (pass --server-home)",
        home.display()
    );
    let key = pm_accounts::ServerKey::load_or_create(&home.join("server.key"))?;
    let accounts = pm_accounts::Accounts::open(&home.join("server.db"), key)?;
    let token = accounts.reset_owner()?;
    let base = public_url.map(|u| u.trim_end_matches('/')).unwrap_or("https://<this server's address>");
    Ok(format!("{base}/#setup={}", token.token.expose()))
}

/// What `proxymind serve` was given.
struct ServeArgs {
    accounts: bool,
    server_home: Option<PathBuf>,
    listen: SocketAddr,
    public_url: Option<String>,
    allowed_host: Vec<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_self_signed: bool,
    behind_proxy: bool,
    trusted_proxy: Vec<IpAddr>,
    proxy: Option<SocketAddr>,
    no_http2: bool,
}

/// `proxymind serve --accounts`: the project server (ADR-0022 step 4).
async fn serve_command(cli: &Cli, a: ServeArgs) -> Result<()> {
    use pm_api::listen::{ListenInput, TlsKind};
    anyhow::ensure!(
        a.accounts,
        "`proxymind serve` runs the project server with accounts: add --accounts (for one person on one machine use \
         `proxymind ui`)"
    );
    anyhow::ensure!(
        !(a.tls_cert.is_some() && a.tls_self_signed),
        "choose one certificate source: --tls-cert/--tls-key or --tls-self-signed"
    );
    let tls_kind = match (&a.tls_cert, &a.tls_key, a.tls_self_signed) {
        (Some(_), Some(_), false) => TlsKind::Own,
        (None, None, true) => TlsKind::SelfSigned,
        (None, None, false) => TlsKind::None,
        _ => anyhow::bail!("--tls-cert and --tls-key go together"),
    };
    // Decide before anything is opened or bound: a refused combination touches nothing.
    let plan = pm_api::listen::plan(&ListenInput {
        listen: a.listen,
        tls: tls_kind,
        behind_proxy: a.behind_proxy,
        trusted_proxies: &a.trusted_proxy,
        public_url: a.public_url.as_deref(),
        extra_hosts: &a.allowed_host,
    })
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Bind first: a port that is taken fails before anything is opened or printed.
    let l = tokio::net::TcpListener::bind(a.listen).await.with_context(|| format!("binding {}", a.listen))?;
    let server_home = server_home_dir(cli, a.server_home.as_deref())?;
    private_dir(&server_home)?;
    // server.key: created 0600, refused when other users can read it.
    let key = pm_accounts::ServerKey::load_or_create(&server_home.join("server.key"))?;
    let accounts = Arc::new(pm_accounts::Accounts::open(&server_home.join("server.db"), key)?);

    let home = home_dir(cli)?;
    let service = Arc::new(open_service(&cli.project, None)?);
    // The project's audit chain is keyed with a key derived from the server key (agents and members cannot read it).
    let audit_key =
        pm_service::pm_policy::audit::HmacKey::new(&accounts.server_key().derive(pm_accounts::KeyPurpose::AuditChain))?;
    service.set_audit_security(pm_service::AuditSecurity { key: Some(Arc::new(audit_key)), ..Default::default() });
    let rt = Runtime { proxy: a.proxy, no_http2: a.no_http2, open_browser_as: None };
    let setup = start_runtime(cli, &service, &home, rt).await?;

    let tls = match tls_kind {
        TlsKind::None => None,
        TlsKind::Own => {
            let (Some(cert), Some(key)) = (&a.tls_cert, &a.tls_key) else {
                anyhow::bail!("--tls-cert and --tls-key go together")
            };
            Some(pm_tls::server::ServerTls::from_files(cert, key)?)
        }
        TlsKind::SelfSigned => {
            let (tls, made) = pm_tls::server::ServerTls::self_signed(&server_home, &plan.certificate_names(a.listen))?;
            out!("Self-signed certificate: {}", made.cert_path.display());
            out!("Pin (SHA-256 of its public key): {}", made.pin);
            out!("Clients that pin this server's key check for that value; keep it where your team can compare it.");
            if made.new_key {
                eprintln!("This is a new key: clients that pinned an earlier one must confirm the new pin.");
            }
            Some(tls)
        }
    };

    // The first owner: a one-time setup URL, printed every start until an owner exists.
    let accounts_for_setup = accounts.clone();
    let wait = tokio::task::spawn_blocking(move || -> Result<Option<pm_accounts::SetupToken>> {
        Ok(if accounts_for_setup.has_server_admin()? { None } else { Some(accounts_for_setup.create_setup_token()?) })
    })
    .await??;
    if let Some(t) = wait {
        out!("This server has no owner yet. Open this URL within the hour to create one (it works once):");
        out!("  {}/#setup={}", plan.public_origin, t.token.expose());
        eprintln!("(Setup is served over TLS or from this machine only.)");
    }

    let project_id = service.project_id()?;
    let clock: Arc<dyn pm_accounts::Clock> = Arc::new(pm_accounts::SystemClock);
    let sm = pm_api::ServerMode::new(accounts, clock, project_id, plan.clone());
    let state = pm_api::AppState::new(
        service,
        Actor::parse("human:server")?,
        pm_api::new_token()?,
        cli.project.display().to_string(),
    )?
    .with_setup(setup)
    .with_server_mode(sm);
    let how = match (plan.behind_proxy, tls_kind) {
        (true, _) => "behind a reverse proxy",
        (_, TlsKind::None) => "plain HTTP on loopback",
        (_, TlsKind::Own) => "TLS",
        (_, TlsKind::SelfSigned) => "TLS (self-signed)",
    };
    eprintln!("ProxyMind server on {} ({how}), project {}", plan.public_origin, cli.project.display());
    tokio::select! {
        r = pm_api::listen::serve_app(l, pm_api::router(state), tls.map(|t| t.config)) => r?,
        _ = tokio::signal::ctrl_c() => eprintln!("\nShutting down"),
    }
    Ok(())
}

/// What `proxymind ui` and `proxymind serve` run beside the web server: which parts of the runtime to start.
struct Runtime<'a> {
    /// Where the interception proxy listens; `None` runs without it.
    proxy: Option<SocketAddr>,
    no_http2: bool,
    /// Open the built-in browser as this person once the proxy is up.
    open_browser_as: Option<&'a Actor>,
}

/// The parts both `ui` and `serve` start around a project's service: plugins, interrupted AI scans, the proxy with its
/// recorder, intercept queue, rewrite rules, plugin hooks and listeners, the project and ROE watchers, the scheduler,
/// workflow triggers and the integration notifier. Returns what the Proxy setup page shows.
async fn start_runtime(
    cli: &Cli,
    service: &Arc<Service>,
    home: &std::path::Path,
    rt: Runtime<'_>,
) -> Result<pm_api::ProxySetup> {
    attach_plugins(cli, service);
    service.ai_scan_recover()?;
    let mut setup = pm_api::ProxySetup::default();
    if let Some(proxy) = &rt.proxy {
        let ca = Arc::new(CertAuthority::load_or_create(home)?);
        setup = pm_api::ProxySetup { proxy: Some(proxy.to_string()), ca_pem: Some(ca.ca_pem().to_string()) };
        // The Service for this project is in this process: record through its write connection.
        let (recorder, _writer) = Recorder::spawn_shared(service.store_handle());
        service.attach_recorder(&recorder)?;
        let queue = Arc::new(pm_proxy::InterceptQueue::new());
        service.attach_intercept(queue.clone());
        let rewriter = Arc::new(pm_proxy::Rewriter::new());
        service.attach_rewriter(rewriter.clone())?;
        let plugin_hooks = Arc::new(pm_service::pm_plugin::hooks::HookEngine::new());
        service.attach_hooks(plugin_hooks.clone());
        let hooks = pm_proxy::Hooks {
            rewrite: Some(rewriter.clone()),
            intercept: Some(queue),
            network: Some(service.network().clone()),
            http2: !rt.no_http2,
            plugin_hooks: Some(plugin_hooks),
        };
        let p = Proxy::with_hooks(ca.clone(), recorder, false, hooks)?;
        let extra = pm_proxy::Listeners::new(p.clone(), Some(*proxy));
        service.attach_listeners(extra.clone())?;
        pm_service::watch_project(
            &cli.project,
            Some(rewriter),
            service.network().clone(),
            Some(extra),
            service.trust_gate(),
        )?;
        let l = tokio::net::TcpListener::bind(proxy).await.with_context(|| format!("binding proxy on {proxy}"))?;
        pm_proxy::listeners::warn_if_exposed(*proxy);
        tokio::spawn(p.run(l));
        eprintln!("Proxy on http://{proxy} (CA: {})", ca.ca_cert_path().display());
        service.attach_proxy_info(pm_service::ProxyInfo {
            addr: proxy.to_string(),
            ca_pem: ca.ca_pem().to_string(),
            profile_dir: cli.project.with_extension("browser"),
        });
        if let Some(me) = rt.open_browser_as {
            match service.browser_open(me, Default::default()).await {
                Ok(b) => eprintln!("Browser opened at {} (profile {})", b.url, b.profile),
                Err(e) => eprintln!("Could not open the browser: {e}"),
            }
        }
    } else {
        pm_service::watch_project(&cli.project, None, service.network().clone(), None, service.trust_gate())?;
    }
    pm_service::watch_roe(service.clone());
    // Scheduled scans start while the UI server runs.
    tokio::spawn(service.clone().run_scheduler());
    // Workflows a person switched to "run on new traffic" react to exchanges the proxy records.
    tokio::spawn(service.clone().run_workflow_triggers());
    // Slack and webhook notifications a person enabled in this installation, from the event bus.
    tokio::spawn(service.clone().run_integration_notifier());
    Ok(setup)
}

fn open_service(project: &std::path::Path, roe_file: Option<&std::path::Path>) -> Result<Service> {
    let mut store = Store::open(project)?;
    // Whether this installation trusted the project before `roe use` changes it: a person who changes the rules of
    // a project they already trust keeps it trusted; a project that is not trusted stays in safe mode.
    let was_trusted = HOME.get().is_some_and(|h| pm_service::project_trusted_in(&store, h));
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
    let service = Service::new(store, Policy::new(Roe::parse(&text)?))?;
    if let Some(h) = HOME.get() {
        service.attach_trust_home(h.clone());
    }
    if roe_file.is_some() {
        service.note_person_edit(&human_actor(None)?, was_trusted);
    }
    Ok(service)
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
    anyhow::ensure!(
        pm_service::access::Principal::from_actor(&actor).allows(pm_service::access::Perm::ApprovalsDecide),
        "only human:<name> actors can approve"
    );
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

    let matches = <Cli as clap::CommandFactory>::command().get_matches();
    let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches)?;
    if let Ok(h) = home_dir(&cli) {
        let _ = HOME.set(h);
    }
    // `proxymind ci` opens a project only when `--project` is on the command line (not from the environment).
    let project_given = matches.value_source("project") == Some(clap::parser::ValueSource::CommandLine)
        || matches
            .subcommand()
            .is_some_and(|(_, m)| m.value_source("project") == Some(clap::parser::ValueSource::CommandLine));
    match &cli.command {
        Command::Ci(args) => {
            let code = match run_ci(&cli, project_given, args).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("Error: {e:#}");
                    2
                }
            };
            if code != 0 {
                std::process::exit(code);
            }
        }
        Command::Proxy { listen, verify_upstream, no_http2 } => {
            let ca = Arc::new(CertAuthority::load_or_create(&home_dir(&cli)?)?);
            // With a Service for this project in this process, the recorder shares its write connection
            // (ADR-0017); without rules of engagement there is no Service, so it keeps its own connection.
            let service = match open_service(&cli.project, None) {
                Ok(service) => Some(Arc::new(service)),
                Err(_) => {
                    eprintln!("No rules of engagement: in-scope-only match-and-replace rules are off.");
                    None
                }
            };
            let gate = match &service {
                Some(service) => service.trust_gate(),
                None => {
                    let mut store = Store::open(&cli.project)?;
                    pm_service::trust_gate_for(&mut store, HOME.get().cloned())?
                }
            };
            let (recorder, writer) = match &service {
                Some(service) => Recorder::spawn_shared(service.store_handle()),
                None => {
                    let mut store = Store::open(&cli.project)?;
                    store.set_text_extractor(pm_service::searchable);
                    Recorder::spawn(store)
                }
            };
            // In-scope-only rules need the rules of engagement; without
            // them only rules marked "any host" apply.
            let rewriter = Arc::new(pm_proxy::Rewriter::new());
            let plugin_hooks = Arc::new(pm_service::pm_plugin::hooks::HookEngine::new());
            if let Some(service) = service {
                attach_plugins(&cli, &service);
                service.attach_hooks(plugin_hooks.clone());
                service.attach_rewriter(rewriter.clone())?;
                service.attach_recorder(&recorder)?;
                pm_service::watch_roe(service);
            }
            let network = pm_service::pm_replay::Network::new();
            let hooks = pm_proxy::Hooks {
                rewrite: Some(rewriter.clone()),
                network: Some(network.clone()),
                http2: !*no_http2,
                plugin_hooks: Some(plugin_hooks),
                ..Default::default()
            };
            let proxy = Proxy::with_hooks(ca.clone(), recorder, *verify_upstream, hooks)?;
            let extra = pm_proxy::Listeners::new(proxy.clone(), Some(*listen));
            pm_service::watch_project(&cli.project, Some(rewriter), network, Some(extra), gate)?;
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
            out!("  CI runs:    {}", tier_line(&roe, ActorKind::Ci));
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
        Command::AiScan { action } => {
            let service = Arc::new(open_service(&cli.project, None)?);
            attach_plugins(&cli, &service);
            service.ai_scan_recover()?;
            let line = |l: &pm_service::AiScanLog| {
                let t = chrono_like(l.ts_ms);
                format!("{t}  {:<12} {}", l.kind, l.text.lines().next().unwrap_or(""))
            };
            match action {
                AiScanAction::Start { target, focus, max_steps, minutes, max_cost, actor } => {
                    let me = human_actor(actor.as_deref())?;
                    let assistant = Arc::new(pm_assistant::Assistant::new(service.clone())?);
                    let req = pm_service::AiScanRequest {
                        target: target.clone(),
                        focus: focus.clone(),
                        max_steps: *max_steps,
                        max_minutes: *minutes,
                        max_cost: *max_cost,
                    };
                    let scan = assistant.start_ai_scan(&me, req)?;
                    out!(
                        "AI scan #{} on {} (model {}): following; stop it with `proxymind ai-scan stop {}`",
                        scan.id,
                        scan.target,
                        scan.model,
                        scan.id
                    );
                    let mut shown = 0;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        let sc = service.ai_scan_get(scan.id)?;
                        for l in sc.log.iter().skip(shown) {
                            out!("{}", line(l));
                        }
                        shown = sc.log.len();
                        if !matches!(sc.status.as_str(), "running" | "stopping") {
                            out!(
                                "\n{}: {} model calls, {} finding(s){}",
                                sc.status,
                                sc.steps,
                                sc.findings,
                                if sc.error.is_empty() { String::new() } else { format!(" ({})", sc.error) }
                            );
                            if !sc.report.is_empty() {
                                out!("Report: `proxymind ai-scan report {}`", sc.id);
                            }
                            break;
                        }
                    }
                }
                AiScanAction::Status { id: None } => {
                    for sc in service.ai_scan_list(50)? {
                        out!(
                            "#{:<4} {:<9} {:<13} {:>4}/{:<4} steps  {} finding(s)  {}",
                            sc.id,
                            sc.status,
                            sc.phase,
                            sc.steps,
                            sc.max_steps,
                            sc.findings,
                            sc.target
                        );
                    }
                }
                AiScanAction::Status { id: Some(id) } => {
                    let sc = service.ai_scan_get(*id)?;
                    out!(
                        "#{} {} · phase {} · {}/{} steps · {} finding(s) · {}",
                        sc.id,
                        sc.status,
                        sc.phase,
                        sc.steps,
                        sc.max_steps,
                        sc.findings,
                        sc.target
                    );
                    for l in &sc.log {
                        out!("{}", line(l));
                    }
                }
                AiScanAction::Report { id, out } => {
                    let sc = service.ai_scan_get(*id)?;
                    anyhow::ensure!(!sc.report.is_empty(), "scan #{id} has no report yet (status {})", sc.status);
                    match out {
                        Some(p) => {
                            std::fs::write(p, &sc.report)?;
                            out!("✓ report written to {}", p.display());
                        }
                        None => out!("{}", sc.report),
                    }
                }
                AiScanAction::Stop { id, actor } => {
                    let sc = service.ai_scan_stop(&human_actor(actor.as_deref())?, *id)?;
                    out!("#{} {}", sc.id, sc.status);
                }
                AiScanAction::Say { id, text, actor } => {
                    service.ai_scan_message(&human_actor(actor.as_deref())?, *id, text)?;
                    out!("✓ sent to AI scan #{id}");
                }
                AiScanAction::Memory { host } => {
                    let notes = service.memory_list(host.as_deref())?;
                    if notes.is_empty() {
                        out!("No notes saved.");
                    }
                    for m in notes.iter().rev() {
                        out!("#{} {} [{}] {}  ({})", m.id, m.host, m.kind, m.text, m.actor);
                    }
                }
                AiScanAction::Paths { id } => {
                    let paths = service.attack_path_list(*id)?;
                    if paths.is_empty() {
                        out!("No attack paths recorded.");
                    }
                    for p in paths.iter().rev() {
                        out!("#{} [{}] {}", p.id, p.severity, p.title);
                        for (i, st) in p.steps.iter().enumerate() {
                            let f = st.finding_id.map(|f| format!(" (finding #{f})")).unwrap_or_default();
                            out!("  {}. {}{f}", i + 1, st.text);
                        }
                        out!("  → {}", p.impact);
                    }
                }
                AiScanAction::Prompt => {
                    let target = service.policy().roe().include.first().map(|p| p.text.clone()).unwrap_or_default();
                    out!("{}", service.ai_scan_prompt(&target, "")?);
                }
            }
        }
        Command::Evidence { out, all, actor } => {
            let service = open_service(&cli.project, None)?;
            attach_plugins(&cli, &service);
            let (bytes, fingerprint) = service.evidence_pack(&human_actor(actor.as_deref())?, *all)?;
            std::fs::write(out, &bytes)?;
            out!("✓ {} ({} KB), signed by key {fingerprint}", out.display(), bytes.len() / 1024);
            out!(
                "  Give the client this fingerprint separately; they check the pack with `proxymind verify {}`.",
                out.display()
            );
        }
        Command::Regress { action: RegressAction::Export { out, actor } } => {
            let service = open_service(&cli.project, None)?;
            let (bytes, export) = service.regression_zip(&human_actor(actor.as_deref())?)?;
            std::fs::write(out, &bytes)?;
            out!("✓ {}: {} test(s)", out.display(), export.tests.len());
            for s in &export.skipped {
                out!("  no test for #{} {}: {}", s.finding_id, s.title, s.reason);
            }
        }
        Command::Regress { action: RegressAction::Run { paths, target, junit, insecure, json, allow_skipped } } => {
            let mut files = Vec::new();
            for p in paths {
                if p.is_dir() {
                    let mut found: Vec<PathBuf> = std::fs::read_dir(p)?
                        .filter_map(|e| e.ok().map(|e| e.path()))
                        .filter(|f| f.extension().is_some_and(|x| x == "json"))
                        .collect();
                    found.sort();
                    files.extend(found);
                } else {
                    files.push(p.clone());
                }
            }
            if files.is_empty() {
                anyhow::bail!("no test files given");
            }
            let env = |k: &str| std::env::var(k).ok();
            let mut results = Vec::new();
            for f in &files {
                let text = std::fs::read_to_string(f)?;
                let t: pm_service::pm_tools::regress::RegressionTest =
                    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
                let r = pm_service::run_regression(&t, target.as_deref(), !insecure, &env).await;
                if !*json {
                    let mark = match r.outcome.as_str() {
                        "vulnerable" => "✗ STILL VULNERABLE",
                        "fixed" => "✓ fixed",
                        "skipped" => "- skipped",
                        _ => "! error",
                    };
                    out!("{mark:<20} #{} {}  ({})", r.finding_id, r.title, r.detail);
                }
                results.push(r);
            }
            if let Some(j) = junit {
                std::fs::write(j, pm_service::junit(&results))?;
            }
            let still = results.iter().filter(|r| r.outcome == "vulnerable").count();
            let errors = results.iter().filter(|r| r.outcome == "error").count();
            let skipped = results.iter().filter(|r| r.outcome == "skipped").count();
            if *json {
                out!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                out!(
                    "{} test(s): {} still vulnerable, {} fixed, {} skipped, {} error(s)",
                    results.len(),
                    still,
                    results.iter().filter(|r| r.outcome == "fixed").count(),
                    skipped,
                    errors
                );
            }
            match regress_exit_code(still, errors, skipped, *allow_skipped) {
                0 => {}
                2 => {
                    eprintln!(
                        "{skipped} test(s) skipped because a credential variable is not set; they say nothing about \
                         whether the findings are fixed. Set the PM_AUTH_* variables, or pass --allow-skipped."
                    );
                    std::process::exit(2);
                }
                code => std::process::exit(code),
            }
        }
        Command::Changes { save, snapshot, since, json, actor } => {
            let service = open_service(&cli.project, None)?;
            if let Some(name) = save {
                let s = service.model_snapshot_save(&human_actor(actor.as_deref())?, name)?;
                out!("✓ snapshot #{} \"{}\": {} operation(s)", s.id, s.name, s.operations);
                return Ok(());
            }
            let c = match since {
                Some(path) => {
                    let other = pm_service::Service::new(
                        pm_service::pm_store::Store::open(path)?,
                        Policy::new((*service.policy().roe()).clone()),
                    )?;
                    service.model_changes_from(&format!("project {}", path.display()), &other.model_shapes()?)?
                }
                None => {
                    let snaps = service.model_snapshot_list()?;
                    let pick = match snapshot {
                        Some(s) => snaps.iter().find(|x| x.name == *s || x.id.to_string() == *s),
                        None => snaps.first(),
                    };
                    let Some(pick) = pick else {
                        anyhow::bail!(
                            "no such snapshot; save one with `proxymind changes --save NAME` or use --since OTHER.pmproj"
                        )
                    };
                    service.model_changes(pick.id)?
                }
            };
            if *json {
                out!("{}", serde_json::to_string_pretty(&c)?);
            } else {
                out!(
                    "Since {}: {} new, {} changed, {} removed, {} unchanged",
                    c.since,
                    c.added.len(),
                    c.changed.len(),
                    c.removed.len(),
                    c.unchanged
                );
                for r in &c.retest {
                    let f = if r.findings.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "  (findings {})",
                            r.findings.iter().map(|i| format!("#{i}")).collect::<Vec<_>>().join(", ")
                        )
                    };
                    out!("  {:<48} {}{f}", r.operation, r.why);
                }
                for r in &c.removed {
                    out!("  gone: {} {}", r.method, r.template);
                }
            }
        }
        Command::Verify { pack, json } => {
            let bytes = std::fs::read(pack)?;
            let v = pm_service::verify_evidence(&bytes);
            if *json {
                out!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for c in &v.checks {
                    out!("{} {:<10} {}", if c.ok { "✓" } else { "✗" }, c.name, c.detail);
                }
                if let Some(fp) = &v.fingerprint {
                    out!("  Signer: {fp} (compare with the fingerprint the tester gave you)");
                }
                out!("{}", if v.ok { "The pack is intact and consistent." } else { "The pack FAILED verification." });
            }
            if !v.ok {
                std::process::exit(1);
            }
        }
        Command::Recon { action } => {
            let service = open_service(&cli.project, None)?;
            match action {
                ReconAction::Dns { host, resolver, actor } => {
                    let r = service.recon_dns(&human_actor(actor.as_deref())?, host, *resolver).await?;
                    out!("{} (resolver {})", r.host, r.resolver);
                    for rec in &r.records {
                        out!("  {:<6} {:<7} {:<32} {}", rec.kind, rec.ttl, rec.name, rec.value);
                    }
                    for n in &r.notes {
                        out!("  ! {n}");
                    }
                }
                ReconAction::Wayback { host, limit, actor } => {
                    let r = service.recon_wayback(&human_actor(actor.as_deref())?, host, *limit, None).await?;
                    out!("{}: {} archived URLs, {} interesting", r.host, r.total, r.interesting);
                    for c in &r.captures {
                        let st = c.capture.status.map_or("-".to_string(), |s| s.to_string());
                        let note = c.capture.note.map(|n| format!("  [{n}]")).unwrap_or_default();
                        let known = if c.known { "  (seen)" } else { "" };
                        out!("  {st:<4} {}{note}{known}", c.capture.url);
                    }
                }
            }
        }
        Command::Integration { action } => {
            let service = open_service(&cli.project, None)?;
            attach_plugins(&cli, &service);
            let me = human_actor(None)?;
            match action {
                IntegrationAction::List { json } => {
                    let list = service.integration_list(&me)?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&list)?);
                    } else if list.is_empty() {
                        out!("No integrations yet: set one up on the Integrations page.");
                    }
                    for v in list.iter().filter(|_| !*json) {
                        let state = if v.needs_review {
                            "needs review: enable it in this installation"
                        } else if v.active {
                            "on"
                        } else {
                            "off"
                        };
                        out!("{:<20} {:<8} {state}", v.config.name, v.config.kind.as_str());
                        for p in &v.problems {
                            out!("    {p}");
                        }
                        if let Some(e) = &v.last_error {
                            out!("    last error: {}", e.message);
                        }
                    }
                }
                IntegrationAction::Test { name, json } => {
                    let row = service.integration_test(&me, name).await?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&row)?);
                    } else {
                        out!(
                            "{}: {} ({}, {} attempt(s)) {}",
                            row.integration,
                            row.status,
                            row.host,
                            row.attempts,
                            row.detail
                        );
                    }
                    if row.status != "ok" {
                        std::process::exit(1);
                    }
                }
                IntegrationAction::SendFinding { finding, integration, update, json } => {
                    let body = pm_service::SendFindingBody { integration: integration.clone(), update: *update };
                    let link = service.integration_send_finding(&me, *finding, body).await?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&link)?);
                    } else {
                        out!("finding #{finding} → {} {} {}", link.integration, link.key, link.url);
                    }
                }
            }
        }
        Command::Workflow { action } => {
            let service = open_service(&cli.project, None)?;
            match action {
                WorkflowAction::List { json } => {
                    let list = service.workflow_list(&human_actor(None)?)?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&list)?);
                    } else if list.is_empty() {
                        out!("No workflows yet: create one on the Workflows page.");
                    }
                    for w in list.iter().filter(|_| !*json) {
                        let kinds: Vec<&str> = w.steps.iter().map(|s| s.kind()).collect();
                        let trig = if w.trigger.enabled { "  [runs on new traffic]" } else { "" };
                        out!("#{:<3} {:<28} {}{trig}", w.id, w.name, kinds.join(" → "));
                    }
                }
                WorkflowAction::Run { workflow, exchange, approval, json, actor } => {
                    let me = human_actor(actor.as_deref())?;
                    let req = pm_service::WorkflowRunRequest {
                        workflow: workflow.clone(),
                        exchange_id: *exchange,
                        approval_id: approval.clone(),
                    };
                    let run = service.workflow_run(&me, req).await?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&run)?);
                    } else {
                        out!("run #{} of {}: {}", run.id, run.workflow_name, run.status.as_str());
                        for s in &run.steps {
                            let ex = s.exchange_id.map(|e| format!("  → exchange #{e}")).unwrap_or_default();
                            out!(
                                "  {}. {:<9} {:<16} {}{ex}",
                                s.step,
                                s.kind,
                                format!("{:?}", s.status).to_lowercase(),
                                s.message
                            );
                        }
                        for (k, v) in &run.variables {
                            out!("  {k} = {v}");
                        }
                        if let Some(r) = &run.reason {
                            out!("  {r}");
                        }
                        if let Some(p) = &run.pending {
                            out!(
                                "  Approve {} (proxymind approvals), then: proxymind workflow run {} --approval {}{}",
                                p.approval_id,
                                workflow,
                                p.approval_id,
                                exchange.map(|e| format!(" --exchange {e}")).unwrap_or_default()
                            );
                        }
                    }
                    if run.status != pm_service::RunStatus::Ok {
                        std::process::exit(1);
                    }
                }
            }
        }
        Command::Skills { name, focus } => {
            let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://example.invalid/\"]\n")?;
            let service = Service::new(Store::open_in_memory()?, Policy::new(roe))?;
            attach_plugins(&cli, &service);
            match name {
                None => {
                    for s in service.skills_list()? {
                        let mine = if s.source == "user" { " (yours)" } else { "" };
                        out!("{:<18} {}{mine}\n{:<18} {}", s.name, s.title, "", s.description);
                    }
                    out!(
                        "\nPrint one with `proxymind skills <name> [--focus …]`. Add your own as ~/.proxymind/skills/<name>.md."
                    );
                }
                Some(n) => {
                    let mut args = std::collections::BTreeMap::new();
                    if let Some(f) = focus {
                        args.insert("focus".to_string(), f.clone());
                    }
                    let (s, text) = service.skill_get(n, &args)?;
                    out!("# {}\n\n{text}", s.title);
                }
            }
        }
        Command::Update { action } => {
            // Works outside a project: the setting lives in the user's home, and
            // the check isn't target traffic (it never goes through the scope).
            let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://example.invalid/\"]\n")?;
            let service = Service::new(Store::open_in_memory()?, Policy::new(roe))?;
            attach_plugins(&cli, &service);
            let me = human_actor(None)?;
            let st = match action {
                UpdateAction::Check => service.update_check(&me, true).await?,
                UpdateAction::Status => service.update_get()?,
                UpdateAction::On => service.update_set(&me, true)?,
                UpdateAction::Off => service.update_set(&me, false)?,
            };
            out!("ProxyMind {} · daily update check: {}", st.current, if st.state.enabled { "on" } else { "off" });
            match (&st.state.latest, st.available) {
                (Some(l), true) => out!("A newer release is out: {l}  {}", st.state.url.as_deref().unwrap_or("")),
                (Some(l), false) => out!("Up to date (newest release: {l})."),
                (None, _) => out!("Not checked yet: run `proxymind update check`."),
            }
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
        Command::Token { action } => token_command(&cli, action)?,
        Command::Login { url, pin, token_env } => {
            let home = home_dir(&cli)?;
            let token = remote::read_token(token_env.as_deref())?;
            let done = remote::login(&home, url, pin.as_deref(), &token).await?;
            out!("Signed in to {} as {} (project {}).", done.url, done.you_are, done.project);
            out!("Saved the address, pin and token in {} (owner-only).", done.saved_to.display());
            out!("Use it with: proxymind mcp --server {}", done.url);
        }
        Command::Logout { url } => {
            let home = home_dir(&cli)?;
            if remote::forget_server(&home, url)? {
                out!("Forgot {url}. (The token still works until it is revoked on the server.)");
            } else {
                out!("No saved server {url}.");
            }
        }
        Command::Mcp { server: Some(url), token_env, pin, roe, actor, oast_listen, oast_public_url } => {
            anyhow::ensure!(
                roe.is_none() && oast_listen.is_none() && oast_public_url.is_none(),
                "--roe and --oast-listen belong to a local MCP server; with --server the tools run on the server"
            );
            if actor != "agent:mcp" {
                eprintln!("Note: with --server the agent's identity is the token's, not --actor.");
            }
            let home = home_dir(&cli)?;
            let saved = remote::saved_server(&home, url)?;
            let token = match (token_env, &saved) {
                (Some(var), _) => remote::read_token(Some(var))?,
                (None, Some(s)) => s.token.clone(),
                (None, None) => {
                    anyhow::bail!("no token for {url}: run `proxymind login {url}` first, or pass --token-env VAR")
                }
            };
            // A pin given now wins; else the one saved by `login` (a saved pin is never dropped silently).
            let pin = pin.clone().or_else(|| saved.and_then(|s| s.pin));
            remote::mcp_bridge(remote::Remote::new(url, pin.as_deref(), &token)?).await?;
        }
        Command::Mcp { roe, actor, oast_listen, oast_public_url, .. } => {
            let actor = Actor::parse(actor)?;
            anyhow::ensure!(actor.kind != ActorKind::Human, "the MCP server acts for an agent; use agent:<name>");
            let service = Arc::new(open_service(&cli.project, roe.as_deref())?);
            attach_plugins(&cli, &service);
            if let Some(addr) = oast_listen {
                start_oast(&service, *addr, oast_public_url.clone()).await?;
            }
            pm_service::watch_project(&cli.project, None, service.network().clone(), None, service.trust_gate())?;
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
            let tokens = pm_accounts::TokenFile::open(&home)?;
            let service = Arc::new(open_service(&cli.project, None)?);
            let me = human_actor(actor.as_deref())?;
            let runtime = Runtime {
                proxy: (!*no_proxy).then_some(*proxy),
                no_http2: *no_http2,
                open_browser_as: (*open_browser).then_some(&me),
            };
            let setup = start_runtime(&cli, &service, &home, runtime).await?;
            let state = pm_api::AppState::new(service, me.clone(), token.clone(), cli.project.display().to_string())?
                .with_setup(setup)
                .with_tokens(tokens);
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
        Command::Serve {
            accounts,
            server_home,
            listen,
            public_url,
            allowed_host,
            tls_cert,
            tls_key,
            tls_self_signed,
            behind_proxy,
            trusted_proxy,
            proxy,
            no_http2,
        } => {
            let args = ServeArgs {
                accounts: *accounts,
                server_home: server_home.clone(),
                listen: *listen,
                public_url: public_url.clone(),
                allowed_host: allowed_host.clone(),
                tls_cert: tls_cert.clone(),
                tls_key: tls_key.clone(),
                tls_self_signed: *tls_self_signed,
                behind_proxy: *behind_proxy,
                trusted_proxy: trusted_proxy.clone(),
                proxy: *proxy,
                no_http2: *no_http2,
            };
            serve_command(&cli, args).await?;
        }
        Command::Server { action: ServerAction::ResetOwner { server_home, public_url } } => {
            let home = server_home_dir(&cli, server_home.as_deref())?;
            let url = reset_owner(&home, public_url.as_deref())?;
            out!("All sessions are ended. Open this URL within the hour to create a new owner (it works once):");
            out!("  {url}");
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
            let mut c = service.coverage_proof()?;
            if !all {
                c.cells.retain(|x| matches!(x.status.as_str(), "untested" | "open"));
            }
            if *json {
                out!("{}", serde_json::to_string_pretty(&c)?);
            } else {
                out!(
                    "{} operations: {}% tested · {} vulnerable · {} tested · {} open · {} untested",
                    c.operations,
                    c.percent_tested,
                    c.totals["vulnerable"],
                    c.totals["tested"],
                    c.totals["open"],
                    c.totals["untested"]
                );
                for cell in &c.cells {
                    let param = if cell.param.is_empty() { String::new() } else { format!(" [{}]", cell.param) };
                    let how = if cell.how.is_empty() { String::new() } else { format!("  ({})", cell.how.join("; ")) };
                    out!("{:<10} {:<16} {}{param}{how}", cell.status, cell.vuln_class, cell.operation);
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
                FindingAction::Prove { id } => match id {
                    Some(id) => {
                        let r = service.finding_prove(&me, *id).await?;
                        out!(
                            "{} finding #{} ({}){}",
                            if r.proven { "✓ proven" } else { "✗ not proven" },
                            r.finding_id,
                            r.vuln_class,
                            r.oracle.map(|o| format!(" by {o}")).unwrap_or_default()
                        );
                        for reason in &r.reasons {
                            out!("  {reason}");
                        }
                    }
                    None => {
                        let sweep = service.auto_prove(&me).await?;
                        out!("{} attempted, {} proven", sweep.attempted, sweep.proven);
                        for p in sweep.results.iter().filter(|p| p.proven) {
                            out!(
                                "  ✓ proven {} (finding #{}) by {}",
                                p.vuln_class,
                                p.finding_id,
                                p.oracle.as_deref().unwrap_or("?")
                            );
                        }
                    }
                },
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
        Command::Project { action: ProjectAction::Status { json } } => {
            let view = open_service(&cli.project, None)?.trust_status()?;
            if *json {
                out!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                out!("{}", trust_text(&view, false));
            }
        }
        Command::Project { action: ProjectAction::Trust { yes, actor } } => {
            let service = open_service(&cli.project, None)?;
            let view = service.trust_status()?;
            if !view.safe_mode {
                out!("{} is already trusted in this installation.", cli.project.display());
                return Ok(());
            }
            out!("{}", trust_text(&view, true));
            if !*yes {
                use std::io::IsTerminal;
                anyhow::ensure!(
                    std::io::stdin().is_terminal(),
                    "not a terminal: read the review above, then run again with --yes to trust the project"
                );
                eprint!("Trust this project and switch all of this on? [y/N] ");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                anyhow::ensure!(answer.trim().eq_ignore_ascii_case("y"), "not trusted");
            }
            let req = pm_service::TrustConfirmRequest { digest: Some(view.digest.clone()) };
            let done = service.trust_confirm(&human_actor(actor.as_deref())?, &req)?;
            out!("✓ {} is trusted (by {})", cli.project.display(), done.trusted_by.unwrap_or_default());
            out!("  Running `proxymind ui` or `proxymind proxy` on it picks this up within seconds.");
        }
        Command::Project { action } => project_command(&cli.project, action)?,
        Command::Plugin { action } => {
            let home = home_dir(&cli)?;
            let mut reg = pm_plugin::Registry::load(&home)?;
            match action {
                PluginAction::Keygen { out: path } => {
                    anyhow::ensure!(!path.exists(), "{} exists: choose another file", path.display());
                    let (private, public) = pm_plugin::sign::keygen()?;
                    write_private(path, &private)?;
                    out!("✓ private key written to {} (keep it secret)", path.display());
                    out!("Public key (give this to people who install your plugins):\n{public}");
                }
                PluginAction::Sign { dir, key, signer } => {
                    let private = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;
                    let sig = pm_plugin::sign::sign(dir, &private, signer)?;
                    out!("✓ signed {} as {} (key {})", dir.display(), sig.signer, sig.key);
                }
                PluginAction::Trust { key, name } => {
                    let key = key.trim().to_ascii_lowercase();
                    anyhow::ensure!(
                        key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()),
                        "a public key is 64 hex characters"
                    );
                    let mut keys = pm_plugin::sign::load_trusted(&home)?;
                    keys.retain(|k| k.key != key);
                    keys.push(pm_plugin::sign::TrustedKey { name: name.clone(), key });
                    pm_plugin::sign::save_trusted(&home, &keys)?;
                    out!("✓ trusting {name}");
                }
                PluginAction::Untrust { key } => {
                    let mut keys = pm_plugin::sign::load_trusted(&home)?;
                    let before = keys.len();
                    keys.retain(|k| !k.key.eq_ignore_ascii_case(key.trim()));
                    pm_plugin::sign::save_trusted(&home, &keys)?;
                    out!("{}", if keys.len() < before { "✓ removed" } else { "no such key" });
                }
                PluginAction::Trusted => {
                    for k in pm_plugin::sign::load_trusted(&home)? {
                        out!("{:<20} {}", k.name, k.key);
                    }
                }
                PluginAction::Add { dir, require_signed } => {
                    let p = reg.add_checked(dir, *require_signed)?.clone();
                    reg.save()?;
                    out!("✓ installed {} {} from {}", p.manifest.name, p.manifest.version, p.dir.display());
                    match &p.signature {
                        pm_plugin::sign::Signature::Unsigned => out!("  Unsigned."),
                        pm_plugin::sign::Signature::Signed { signer, trusted, .. } => {
                            out!(
                                "  Signed by {signer}{}",
                                if *trusted { " (trusted key)" } else { " (key not on your trusted list)" }
                            )
                        }
                    }
                    if p.manifest.is_v2() {
                        out!(
                            "  API 2: it asks for the permissions {}. It stays off until you accept them: `proxymind plugin accept {}` or the Plugins page.",
                            p.manifest.declared_permissions().join(", "),
                            p.manifest.name
                        );
                    }
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
                            "{:<20} {:<8} {:<15} {:<3} {:<9} {}  ({})",
                            p.manifest.name,
                            p.manifest.version,
                            p.manifest.kinds().join("+"),
                            if p.enabled { "on" } else { "off" },
                            match &p.signature {
                                pm_plugin::sign::Signature::Unsigned => "unsigned",
                                pm_plugin::sign::Signature::Signed { trusted: true, .. } => "trusted",
                                pm_plugin::sign::Signature::Signed { .. } => "signed",
                            },
                            p.manifest.description,
                            p.dir.display()
                        );
                    }
                    out!("Sandbox: {}", pm_plugin::sandbox::status().summary);
                }
                PluginAction::Enable { name } | PluginAction::Disable { name } => {
                    let on = matches!(action, PluginAction::Enable { .. });
                    reg.set_enabled_checked(name, on)?;
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
                PluginAction::Accept { name } => {
                    let service = open_service(&cli.project, None)?;
                    service.attach_plugin_home(home.clone());
                    let view = service.plugin_accept_permissions(&human_actor(None)?, name)?;
                    if let Some(p) = view.plugins.iter().find(|p| p.name == *name) {
                        out!("✓ accepted for {name}: {}; the plugin is on", p.accepted_permissions.join(", "));
                    }
                    out!("  Hooks stay off until you turn them on (the Plugins page, with `proxymind ui`).");
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
            workflow,
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
                        workflow: workflow.clone(),
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
        Command::Bench { action: BenchAction::Auto { no_discover, no_scan, no_prove, write_checks, json } } => {
            let service = open_service(&cli.project, None)?;
            let me = human_actor(None)?;
            let disc = if *no_discover { None } else { Some(service.auto_discover(&me).await?) };
            let r = service.auto_access_control(&me).await?;
            let graphql = service.graphql_object_access(&me).await?;
            let sweep = if *no_scan { None } else { Some(service.auto_active_sweep(&me).await?) };
            let writes = if *write_checks { Some(service.auto_write_checks(&me).await?) } else { None };
            // Prove last, once every suspected finding the other passes recorded exists.
            let proven = if *no_prove { None } else { Some(service.auto_prove(&me).await?) };
            if *json {
                out!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "discover": disc, "access_control": r, "graphql": graphql, "scan": sweep,
                            "writes": writes, "prove": proven })
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
                    for s in &d.signups {
                        out!("  sign-up example sent: {s}");
                    }
                    for s in &d.xml_examples {
                        out!("  XML example sent: {s}");
                    }
                    if d.robots_found > 0 {
                        out!("  {} page(s) found in folders robots.txt hides", d.robots_found);
                    }
                    for s in &d.versions {
                        out!("  other API version answers: {s}");
                    }
                    for j in d.js.iter().filter(|j| j.scripts > 0 || j.new > 0) {
                        out!(
                            "  JavaScript: {} script(s) read, {} new endpoint(s) mentioned, {} exist",
                            j.scripts,
                            j.new,
                            j.found.len()
                        );
                        for f in j.found.iter().take(20) {
                            out!("    {f}");
                        }
                    }
                    for s in d.skipped.iter().take(10) {
                        out!("  skipped {s}");
                    }
                }
                out!("{} candidates, {} checked, {} leaks", r.candidates, r.checks, r.leaks);
                for l in &r.exposures {
                    out!("  ? suspected exposure {}: {} (finding #{})", l.operation, l.evidence, l.finding_id);
                }
                for l in &graphql {
                    out!("  ? suspected idor {}: {} (finding #{})", l.operation, l.evidence, l.finding_id);
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
                if let Some(w) = &writes {
                    out!("write checks: {} operations, {} requests, {} leads", w.tried, w.requests, w.leads.len());
                    if let Some(p) = &w.pending_approval {
                        out!("  needs approval: {p}");
                    }
                    for l in &w.leads {
                        out!("  ? suspected {} {} (finding #{})", l.check, l.operation, l.finding_id);
                    }
                    for n in &w.notes {
                        out!("  {n}");
                    }
                }
                if let Some(pr) = &proven {
                    out!("prove: {} attempted, {} proven", pr.attempted, pr.proven);
                    for p in pr.results.iter().filter(|p| p.proven) {
                        out!(
                            "  ✓ proven {} (finding #{}) by {}",
                            p.vuln_class,
                            p.finding_id,
                            p.oracle.as_deref().unwrap_or("?")
                        );
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
                AuthzAction::Matrix { prove, max, json, actor } => {
                    let m = service
                        .authz_matrix(
                            &human_actor(actor.as_deref())?,
                            pm_service::AuthzMatrixRequest { prove: *prove, max_operations: *max },
                        )
                        .await?;
                    if *json {
                        out!("{}", serde_json::to_string_pretty(&m)?);
                    } else {
                        let cols: Vec<&str> = m.identities.iter().map(|(n, _)| n.as_str()).collect();
                        out!("{:<48} {}", "OPERATION", cols.iter().map(|c| format!("{c:<14}")).collect::<String>());
                        for r in &m.rows {
                            let cells: String = cols
                                .iter()
                                .map(|c| {
                                    let v = r.cells.get(*c).map_or("-", |x| x.verdict.as_str());
                                    format!(
                                        "{:<14}",
                                        v.replace("same_as_owner", "SAME DATA")
                                            .replace("allowed_different", "own data")
                                    )
                                })
                                .collect();
                            out!("{:<48} {cells}", r.operation.chars().take(47).collect::<String>());
                            for f in &r.flags {
                                let proven = match (f.proven, f.finding_id) {
                                    (Some(true), Some(id)) => format!(" — proven, finding #{id}"),
                                    (Some(false), _) => " — not proven".into(),
                                    _ => String::new(),
                                };
                                out!("    ! {} {}: {}{proven}", f.kind, f.identity, f.why);
                            }
                        }
                        out!("{} operation(s), {} flagged, {} proven", m.rows.len(), m.flagged, m.proven);
                        for s in &m.skipped {
                            out!("  skipped {s}");
                        }
                    }
                }
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
        Command::Audit {
            action: AuditAction::Verify { anchor, checkpoint, checkpoint_key, key_file, require_keyed },
        } => {
            let store = Store::open(&cli.project)?;
            let mut checkpoints = Vec::new();
            for f in checkpoint {
                let text = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
                checkpoints.extend(pm_service::pm_policy::checkpoint::Checkpoint::parse_many(&text)?);
            }
            let key: Option<std::sync::Arc<dyn pm_service::pm_policy::audit::AuditKey>> = match key_file {
                Some(f) => Some(std::sync::Arc::new(pm_service::pm_policy::audit::HmacKey::from_file_bytes(
                    &std::fs::read(f).with_context(|| format!("reading {}", f.display()))?,
                )?)),
                None => None,
            };
            let trusted_signer = home_dir(&cli).ok().and_then(|h| pm_service::checkpoint_signer_public(&h));
            let report = pm_service::verify_audit_report(
                &store,
                &pm_service::AuditVerifyOptions {
                    key,
                    require_keyed: *require_keyed,
                    checkpoints,
                    trusted_signer,
                    pinned_fingerprint: checkpoint_key.clone(),
                },
            );
            let records = store.audit_records()?;
            let hex = |h: &[u8]| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let n = report.records;
            if let Some(a) = anchor {
                let a = a.trim().to_ascii_lowercase();
                anyhow::ensure!(a.len() >= 12 && a.chars().all(|c| c.is_ascii_hexdigit()), "give 12+ hex digits");
                let Some(at) = records.iter().position(|r| hex(&r.hash).starts_with(&a)) else {
                    anyhow::bail!("anchor {a} is not in the audit log: records were removed from the end");
                };
                out!("✓ anchor found at record {} of {n}", at + 1);
            }
            let head = &report.head[..report.head.len().min(24)];
            out!(
                "{} records: {} version 1, {} version 2 ({} keyed)",
                report.records,
                report.v1_records,
                report.v2_records,
                report.keyed_records
            );
            out!("  key check: {}: {}", report.key_check, report.key_note);
            let c = &report.checkpoints;
            match c.status.as_str() {
                "none" => out!("  checkpoints: none (write one with `proxymind audit checkpoint -o FILE`)"),
                st => {
                    out!(
                        "  checkpoints: {st} ({} stored, {} given; newest covers record {}, signer {}{})",
                        c.stored,
                        c.supplied,
                        c.latest_seq.unwrap_or(0),
                        c.fingerprint.clone().unwrap_or_default(),
                        if c.signer_pinned { "" } else { ", signer not pinned: pass --checkpoint-key" }
                    );
                }
            }
            if let Some(e) = &report.error {
                anyhow::bail!("audit log verification FAILED: {e}");
            }
            out!("✓ audit log intact: {n} records, chain verified (head {head})");
        }
        Command::Audit { action: AuditAction::Checkpoint { out: file, actor } } => {
            let service = open_service(&cli.project, None)?;
            attach_plugins(&cli, &service);
            let cp = service.audit_checkpoint(&human_actor(actor.as_deref())?)?;
            let text = serde_json::to_string_pretty(&cp)?;
            match file {
                Some(f) => {
                    std::fs::write(f, text + "\n")?;
                    out!("✓ checkpoint at record {} written to {}", cp.seq, f.display());
                    out!("  signer {}; head {}", cp.fingerprint(), &cp.head[..24]);
                    out!(
                        "  Keep the file where whoever can write the project file cannot; check with `proxymind audit verify --checkpoint {}`.",
                        f.display()
                    );
                }
                None => out!("{text}"),
            }
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

/// A project's trust state for a terminal; `full` adds everything the file would switch on.
fn trust_text(v: &pm_service::TrustView, full: bool) -> String {
    let mut t = String::new();
    if v.safe_mode {
        t.push_str("SAFE MODE: this installation does not trust this project");
        if v.changed_since_trust {
            t.push_str(" (its settings changed since it was trusted)");
        }
        t.push_str(
            ".
Held back until you trust it:
",
        );
        for h in &v.held_back {
            t.push_str(&format!(
                "  - {} ({})
",
                h.what, h.why
            ));
        }
    } else {
        t.push_str(&format!(
            "Trusted ({} by {}). Nothing is held back.
",
            v.basis.as_deref().unwrap_or("?"),
            v.trusted_by.as_deref().unwrap_or("?")
        ));
    }
    if full {
        let r = &v.review;
        let mut section = |title: &str, items: &[pm_service::ReviewItem]| {
            if items.is_empty() {
                return;
            }
            t.push_str(&format!("{title}:\n"));
            for i in items {
                let by = i.claimed_by.as_deref().map(|b| format!(" [the file says: {b}]")).unwrap_or_default();
                t.push_str(&format!("  - {}: {}{by}\n", i.what, i.detail));
            }
        };
        section("Listeners", &r.listeners);
        section("Upstream proxy rules", &r.upstream_rules);
        section("Other network settings", &r.network_other);
        section("Match-and-replace rules", &r.rewrite_rules);
        section("Scan schedules", &r.schedules);
        section("Workflow triggers", &r.triggers);
        section("Session rules and macros", &r.session);
        section("Assistant", &r.assistant);
        if let Some(roe) = &r.roe_text {
            t.push_str(&format!("Rules of engagement (written by whoever made the file):\n{roe}\n"));
        }
    }
    t
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
        ProjectAction::Status { .. } | ProjectAction::Trust { .. } => unreachable!("handled before"),
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

/// Writes a secret file readable by the owner only (where the OS has modes).
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// `HH:MM:SS` (UTC) for a log line.
fn chrono_like(ms: i64) -> String {
    let secs = ms.div_euclid(1000).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

/// Exit code of `regress run`: 1 if a finding is still there or a test can't
/// tell, 2 if only skipped tests stand between the run and a pass (a missing
/// secret in CI must not look like "all fixed"), else 0.
fn regress_exit_code(still: usize, errors: usize, skipped: usize, allow_skipped: bool) -> i32 {
    if still > 0 || errors > 0 {
        1
    } else if skipped > 0 && !allow_skipped {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::regress_exit_code;

    #[test]
    fn skipped_regression_tests_fail_the_run_unless_allowed() {
        assert_eq!(regress_exit_code(0, 0, 0, false), 0);
        assert_eq!(regress_exit_code(0, 0, 3, false), 2, "an unset credential variable must not pass in CI");
        assert_eq!(regress_exit_code(0, 0, 3, true), 0);
        assert_eq!(regress_exit_code(1, 0, 3, true), 1, "a finding still there wins over skipped");
        assert_eq!(regress_exit_code(0, 2, 0, false), 1);
    }
}
