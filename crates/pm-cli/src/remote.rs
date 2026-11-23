//! Talking to a project server (ADR-0022 step 5): `proxymind login`, `proxymind logout` and the stdio-to-HTTPS MCP
//! bridge (`proxymind mcp --server`).
//!
//! * **Saved servers** are in `<home>/servers.json` (0600, refused when group or others can read it): per server the
//!   origin, the pin when its certificate is self-signed, and the `pm3_` token. A saved token is a credential like
//!   the install token in `<home>/api-token`: anything that can read the file can act as that agent.
//! * **TLS.** With no pin the certificate must verify against the bundled public roots (the same roots upstream
//!   verification uses); a bad certificate fails. With a pin the server's public key must hash to it
//!   (`pm_tls::server::pin_client_config`), whatever the name or dates say. A mismatch is an error that names both
//!   pins and is never retried with weaker checks. `http://` is accepted for loopback addresses only: a token does not
//!   travel in clear text across a network.
//! * **The client** is one small HTTP/1.1 request per connection (`Connection: close`): the bridge's traffic is a few
//!   JSON-RPC messages, and not holding a connection open means no state to go stale.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use pm_tls::server::Pin;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

/// The most a response may hold (the bridge reads whole answers).
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A tool call can run for a while (a scan step, a race); this only stops a connection that is truly stuck.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

// ---- saved servers --------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SavedServer {
    /// `https://host[:port]`, no path.
    pub url: String,
    /// `sha256:<base64>` of the server certificate's public key; `None` for a certificate a public CA signed.
    #[serde(default)]
    pub pin: Option<String>,
    /// The `pm3_` token. Secret.
    pub token: String,
    pub saved_at: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct ServersFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    servers: Vec<SavedServer>,
}

pub fn servers_path(home: &Path) -> PathBuf {
    home.join("servers.json")
}

fn load(home: &Path) -> Result<ServersFile> {
    let path = servers_path(home);
    match std::fs::metadata(&path) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path)?.permissions().mode();
                anyhow::ensure!(
                    mode & 0o077 == 0,
                    "{} is readable by other users (mode {:o}); chmod 600 it, and consider its tokens exposed",
                    path.display(),
                    mode & 0o777
                );
            }
            let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let f: ServersFile = serde_json::from_str(&text)
                .with_context(|| format!("{} is damaged: fix or remove it", path.display()))?;
            anyhow::ensure!(f.version <= 1, "{} was written by a newer ProxyMind", path.display());
            Ok(f)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ServersFile { version: 1, servers: Vec::new() }),
        Err(e) => Err(e.into()),
    }
}

fn save(home: &Path, f: &ServersFile) -> Result<()> {
    std::fs::create_dir_all(home).with_context(|| format!("creating {}", home.display()))?;
    let path = servers_path(home);
    let tmp = path.with_extension("json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    std::io::Write::write_all(&mut file, serde_json::to_string_pretty(f)?.as_bytes())?;
    std::io::Write::write_all(&mut file, b"\n")?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// The saved entry for `url` (compared as an origin), if any.
pub fn saved_server(home: &Path, url: &str) -> Result<Option<SavedServer>> {
    let origin = normalise_url(url)?.origin;
    Ok(load(home)?.servers.into_iter().find(|s| s.url == origin))
}

/// Saves or replaces the entry for `server.url`.
pub fn save_server(home: &Path, server: SavedServer) -> Result<()> {
    let mut f = load(home)?;
    f.version = 1;
    f.servers.retain(|s| s.url != server.url);
    f.servers.push(server);
    save(home, &f)
}

/// Removes the entry for `url`; false when there was none.
pub fn forget_server(home: &Path, url: &str) -> Result<bool> {
    let origin = normalise_url(url)?.origin;
    let mut f = load(home)?;
    let before = f.servers.len();
    f.servers.retain(|s| s.url != origin);
    let removed = f.servers.len() != before;
    if removed {
        save(home, &f)?;
    }
    Ok(removed)
}

// ---- addresses ------------------------------------------------------------------------------------------------

pub struct Target {
    /// `https://host[:port]`, lower case, default port left out.
    pub origin: String,
    pub https: bool,
    /// What to connect to and to name in TLS (an IPv6 address without brackets).
    pub host: String,
    pub port: u16,
    /// The `Host` header.
    pub host_header: String,
}

/// Accepts `https://host[:port]` (and `http://` for loopback addresses); refuses anything with credentials, a path
/// or a query, so what is saved is exactly an origin.
pub fn normalise_url(raw: &str) -> Result<Target> {
    let u = url::Url::parse(raw.trim()).with_context(|| format!("{raw:?} is not a URL like https://host:7777"))?;
    anyhow::ensure!(
        u.username().is_empty() && u.password().is_none() && u.query().is_none() && u.fragment().is_none(),
        "give the server's address only (https://host[:port]), without credentials, a query or a fragment"
    );
    anyhow::ensure!(
        matches!(u.path(), "" | "/"),
        "give the server's address only (https://host[:port]); ProxyMind adds /api/v1 itself"
    );
    let https = match u.scheme() {
        "https" => true,
        "http" => false,
        other => anyhow::bail!("the scheme must be https (or http for a loopback address), not {other}"),
    };
    let (host, header_host) = match u.host().context("the URL has no host")? {
        url::Host::Domain(d) => (d.to_ascii_lowercase(), d.to_ascii_lowercase()),
        url::Host::Ipv4(a) => (a.to_string(), a.to_string()),
        url::Host::Ipv6(a) => (a.to_string(), format!("[{a}]")),
    };
    if !https {
        let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
        anyhow::ensure!(
            loopback,
            "http:// is accepted for loopback addresses only: a token must not travel in clear text; use https:// (and \
             --pin for a self-signed certificate)"
        );
    }
    let port = u.port_or_known_default().context("the URL has no port")?;
    let default = if https { 443 } else { 80 };
    let host_header = if port == default { header_host.clone() } else { format!("{header_host}:{port}") };
    let origin = format!("{}://{host_header}", u.scheme());
    Ok(Target { origin, https, host, port, host_header })
}

// ---- the client -----------------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum RemoteError {
    /// The certificate did not verify, or the key does not match the pin. Never retried with weaker checks.
    Tls(String),
    Connect(String),
    Http(String),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteError::Tls(m) => write!(f, "TLS verification failed: {m}"),
            RemoteError::Connect(m) => write!(f, "cannot reach the server: {m}"),
            RemoteError::Http(m) => write!(f, "bad answer from the server: {m}"),
        }
    }
}

impl std::error::Error for RemoteError {}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The server's own words for an error (`error`, and `code` when there is one), never the whole body.
    pub fn error_text(&self) -> String {
        match self.json() {
            Some(v) => {
                let msg = v.get("error").and_then(Value::as_str).unwrap_or("no message");
                match v.get("code").and_then(Value::as_str) {
                    Some(code) => format!("{msg} ({code})"),
                    None => msg.to_string(),
                }
            }
            None => String::from_utf8_lossy(&self.body).chars().take(200).collect(),
        }
    }
}

/// One server, one way of verifying it, one token.
pub struct Remote {
    target: Target,
    tls: Option<pm_tls::TlsConnector>,
    token: String,
}

impl Remote {
    /// `pin`: the server's key pin (`sha256:…`), for a self-signed certificate; `None` verifies against the public
    /// roots.
    pub fn new(url: &str, pin: Option<&str>, token: &str) -> Result<Self> {
        let target = normalise_url(url)?;
        let tls = if target.https {
            let cfg = match pin {
                Some(p) => {
                    let pin: Pin = p.parse().map_err(|e| anyhow::anyhow!("--pin: {e}"))?;
                    pm_tls::server::pin_client_config(pin, &[b"http/1.1"])?
                }
                None => pm_tls::upstream_client_config(true)?,
            };
            Some(pm_tls::TlsConnector::from(cfg))
        } else {
            anyhow::ensure!(pin.is_none(), "a pin is for https:// servers");
            None
        };
        Ok(Self { target, tls, token: token.to_string() })
    }

    pub fn origin(&self) -> &str {
        &self.target.origin
    }

    /// One request; the answer is read whole.
    pub async fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Response, RemoteError> {
        let work = self.request_inner(method, path, body);
        match tokio::time::timeout(REQUEST_TIMEOUT, work).await {
            Ok(r) => r,
            Err(_) => Err(RemoteError::Http("the server did not answer in time".into())),
        }
    }

    async fn request_inner(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Response, RemoteError> {
        let t = &self.target;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((t.host.as_str(), t.port)))
            .await
            .map_err(|_| RemoteError::Connect(format!("{} did not answer", t.origin)))?
            .map_err(|e| RemoteError::Connect(format!("{}: {e}", t.origin)))?;
        let body = body.unwrap_or_default();
        // The token goes in the header only. The request text is built here and never logged.
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nUser-Agent: proxymind/{}\r\n\
             Accept: application/json\r\nConnection: close\r\n",
            t.host_header,
            self.token,
            env!("CARGO_PKG_VERSION")
        );
        if !body.is_empty() || method == "POST" {
            head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        match &self.tls {
            Some(connector) => {
                let name = pm_tls::server_name(&t.host).map_err(|e| RemoteError::Connect(e.to_string()))?;
                let stream = connector.connect(name, tcp).await.map_err(|e| RemoteError::Tls(tls_reason(&e)))?;
                exchange(stream, head.as_bytes(), body).await
            }
            None => exchange(tcp, head.as_bytes(), body).await,
        }
    }
}

/// The text of a failed handshake: the verifier's own words (they name both pins on a mismatch), without the wrapping.
fn tls_reason(e: &std::io::Error) -> String {
    let text = e.to_string();
    text.strip_prefix("unexpected error: ").map(str::to_string).unwrap_or(text)
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    head: &[u8],
    body: &[u8],
) -> Result<Response, RemoteError> {
    let io = |e: std::io::Error| RemoteError::Http(e.to_string());
    s.write_all(head).await.map_err(io)?;
    s.write_all(body).await.map_err(io)?;
    s.flush().await.map_err(io)?;
    let mut raw = Vec::new();
    let mut limited = (&mut s).take(MAX_RESPONSE as u64 + 1);
    // A server that closes without a TLS close_notify is read as ended: the framing below decides if it was complete.
    let _ = limited.read_to_end(&mut raw).await;
    if raw.len() > MAX_RESPONSE {
        return Err(RemoteError::Http("the answer is too large".into()));
    }
    parse_response(&raw)
}

/// Status, then the body by `Content-Length` or `chunked` (else what arrived before the close).
pub fn parse_response(raw: &[u8]) -> Result<Response, RemoteError> {
    let bad = |m: &str| RemoteError::Http(m.to_string());
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| bad("no complete answer"))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| bad("the answer's headers are not text"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| bad("no status line"))?;
    let status: u16 =
        status_line.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| bad("no status in the answer"))?;
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                length = v.trim().parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let rest = &raw[end + 4..];
    let body = if status == 204 || status == 304 || (100..200).contains(&status) {
        Vec::new()
    } else if chunked {
        dechunk(rest).ok_or_else(|| bad("a chunked answer was cut short"))?
    } else if let Some(n) = length {
        if rest.len() < n {
            return Err(bad("the answer was cut short"));
        }
        rest[..n].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Response { status, body })
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&data[..eol]).ok()?.split(';').next()?.trim(), 16).ok()?;
        data = &data[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if data.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

// ---- login, logout --------------------------------------------------------------------------------------------

/// Reads the token: from the named environment variable, else a hidden prompt on a terminal, else one line of stdin.
pub fn read_token(token_env: Option<&str>) -> Result<String> {
    use std::io::IsTerminal;
    let raw = match token_env {
        Some(var) => std::env::var(var).with_context(|| format!("the environment variable {var} is not set"))?,
        None if std::io::stdin().is_terminal() => rpassword::prompt_password("Token (input is hidden): ")?,
        None => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    let token = raw.trim().to_string();
    anyhow::ensure!(!token.is_empty(), "no token given");
    anyhow::ensure!(
        pm_accounts::token_shape(&token).is_some(),
        "that is not a ProxyMind token: they look like pm3_agent_… (make one in the web UI or with `proxymind token \
         create`)"
    );
    Ok(token)
}

/// What `GET /api/v1/status` says about who the token is. `Err` carries the reason in words a person can act on.
pub async fn whoami(remote: &Remote) -> Result<Value> {
    let r = remote.request("GET", "/api/v1/status", None).await.map_err(|e| match e {
        RemoteError::Tls(m) => anyhow::anyhow!(
            "TLS verification failed: {m}\nThe connection was not made, and nothing was saved. For a self-signed server pass --pin sha256:… \
             (the server printed it at start); a pin that no longer matches means the server's key changed or this is \
             not the server you meant: confirm the new pin with whoever runs it."
        ),
        other => anyhow::anyhow!("{other}"),
    })?;
    match r.status {
        200 => r.json().context("the server's status answer was not JSON: is this a ProxyMind server?"),
        401 => anyhow::bail!("the server refused the token: {}", r.error_text()),
        s => anyhow::bail!("the server answered {s}: {}", r.error_text()),
    }
}

pub struct LoginOutcome {
    pub url: String,
    pub you_are: String,
    pub project: String,
    pub saved_to: PathBuf,
}

/// `proxymind login URL [--pin …]`: verifies the server (pin or public roots), checks the token by asking who it is,
/// and only then saves. A pin saved for this server is used when none is given; it is replaced only by one given on
/// the command line.
pub async fn login(home: &Path, url: &str, pin: Option<&str>, token: &str) -> Result<LoginOutcome> {
    let origin = normalise_url(url)?.origin;
    let previous = saved_server(home, &origin)?;
    let effective_pin = pin.map(str::to_string).or_else(|| previous.and_then(|p| p.pin));
    let remote = Remote::new(&origin, effective_pin.as_deref(), token)?;
    let who = whoami(&remote).await?;
    let canonical_pin = effective_pin
        .as_deref()
        .map(|p| p.parse::<Pin>().map(|p| p.to_string()))
        .transpose()
        .map_err(|e| anyhow::anyhow!("--pin: {e}"))?;
    save_server(
        home,
        SavedServer {
            url: origin.clone(),
            pin: canonical_pin,
            token: token.to_string(),
            saved_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
                .unwrap_or(0),
        },
    )?;
    Ok(LoginOutcome {
        url: origin,
        you_are: who["you_are"].as_str().unwrap_or("unknown").to_string(),
        project: who["project"].as_str().unwrap_or("").to_string(),
        saved_to: servers_path(home),
    })
}

// ---- the MCP bridge -------------------------------------------------------------------------------------------

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The request ids in a line (one message or a batch), for answering with errors when the server cannot be reached.
fn ids_of(msg: &Value) -> Vec<Value> {
    match msg {
        Value::Array(a) => a.iter().filter_map(|m| m.get("id").cloned()).collect(),
        m => m.get("id").cloned().into_iter().collect(),
    }
}

/// What the bridge answers a client when the server could not give an answer: one error per request id (none for
/// notifications), as one message or, for a batch, an array.
fn failure_reply(msg: &Value, code: i64, text: &str) -> Option<Value> {
    let ids = ids_of(msg);
    if ids.is_empty() {
        return None;
    }
    match msg {
        Value::Array(_) => Some(Value::Array(ids.iter().map(|id| rpc_error(id, code, text)).collect())),
        _ => Some(rpc_error(&ids[0], code, text)),
    }
}

/// Reads newline-delimited JSON-RPC on stdin and posts each message to the server's `/api/v1/mcp` with the token;
/// writes each answer on stdout. The server decides who the agent is (the token's actor); nothing here names one. A
/// failed certificate or pin check ends the bridge at once (never retried, never weakened); any other failure is
/// answered to the client as a JSON-RPC error and the bridge goes on.
pub async fn mcp_bridge(remote: Remote) -> Result<()> {
    let remote = Arc::new(remote);
    // Fail early and in words: wrong pin, bad certificate, refused token, not a ProxyMind server.
    let who = whoami(&remote).await?;
    eprintln!(
        "ProxyMind MCP bridge to {} as {} (project {})",
        remote.origin(),
        who["you_are"].as_str().unwrap_or("?"),
        who["project"].as_str().unwrap_or("?")
    );
    let out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let line = tokio::select! {
            l = lines.next_line() => match l? {
                Some(l) => l,
                None => break,
            },
            Some(why) = fatal_rx.recv() => {
                tasks.abort_all();
                anyhow::bail!("{why}");
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let (remote, out, fatal_tx) = (remote.clone(), out.clone(), fatal_tx.clone());
        tasks.spawn(async move {
            let parsed: Option<Value> = serde_json::from_str(&line).ok();
            let reply: Option<Value> = match remote.request("POST", "/api/v1/mcp", Some(line.as_bytes())).await {
                Ok(r) if r.status == 200 => r.json(),
                Ok(r) if r.status == 204 => None,
                Ok(r) => {
                    let why = match r.status {
                        401 => "the server refused the token (revoked, expired or wrong)".to_string(),
                        403 => format!("the server refused this: {}", r.error_text()),
                        s => format!("the server answered {s}: {}", r.error_text()),
                    };
                    // The server's own JSON-RPC error (a parse error, say) is passed on as it is.
                    match r.json().filter(|v| v.get("jsonrpc").is_some()) {
                        Some(v) => Some(v),
                        None => parsed.as_ref().and_then(|m| failure_reply(m, -32000, &why)),
                    }
                }
                Err(RemoteError::Tls(m)) => {
                    let _ = fatal_tx.send(format!("TLS verification failed: {m}"));
                    parsed.as_ref().and_then(|m| failure_reply(m, -32000, "TLS verification of the server failed"))
                }
                Err(e) => parsed.as_ref().and_then(|m| failure_reply(m, -32000, &e.to_string())),
            };
            if let Some(reply) = reply {
                let mut out = out.lock().await;
                let _ = out.write_all(format!("{reply}\n").as_bytes()).await;
                let _ = out.flush().await;
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_origins_and_http_is_loopback_only() {
        let t = normalise_url("https://PM.Example.com:7777/").unwrap();
        assert_eq!(
            (t.origin.as_str(), t.host.as_str(), t.port, t.https),
            ("https://pm.example.com:7777", "pm.example.com", 7777, true)
        );
        assert_eq!(normalise_url("https://pm.example.com").unwrap().origin, "https://pm.example.com");
        assert_eq!(normalise_url("https://pm.example.com:443").unwrap().origin, "https://pm.example.com");
        assert_eq!(normalise_url("http://127.0.0.1:7777").unwrap().host_header, "127.0.0.1:7777");
        assert_eq!(normalise_url("http://localhost:7777").unwrap().port, 7777);
        let v6 = normalise_url("http://[::1]:7777").unwrap();
        assert_eq!((v6.host.as_str(), v6.host_header.as_str()), ("::1", "[::1]:7777"));
        for bad in [
            "http://pm.example.com",
            "http://10.0.0.5:7777",
            "ftp://pm.example.com",
            "https://user:pw@pm.example.com",
            "https://pm.example.com/api",
            "https://pm.example.com/?x=1",
            "https://pm.example.com/#frag",
            "pm.example.com",
            "",
        ] {
            assert!(normalise_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn answers_are_framed_by_length_by_chunks_and_by_status() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, b"hello".as_slice()));
        let r = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.body, b"abcde");
        assert!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap().body.is_empty());
        let r = parse_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil the close").unwrap();
        assert_eq!(r.body, b"until the close");
        for cut in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
            b"HTTP/1.1 200",
            b"",
            b"garbage\r\n\r\n",
        ] {
            assert!(parse_response(cut).is_err(), "{:?}", String::from_utf8_lossy(cut));
        }
    }

    #[test]
    fn a_failed_server_is_answered_per_request_id() {
        let one = json!({"jsonrpc": "2.0", "id": 7, "method": "ping"});
        assert_eq!(failure_reply(&one, -32000, "x").unwrap()["id"], 7);
        assert!(
            failure_reply(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), -32000, "x").is_none()
        );
        let batch = json!([{"id": 1, "method": "a"}, {"method": "n"}, {"id": "b", "method": "c"}]);
        let r = failure_reply(&batch, -32000, "x").unwrap();
        assert_eq!(r.as_array().unwrap().len(), 2);
        assert_eq!(r[1]["id"], "b");
    }

    #[test]
    fn saved_servers_are_private_and_replaced_by_origin() {
        let dir = std::env::temp_dir().join(format!("pm-cli-servers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let entry = |pin: Option<&str>, token: &str| SavedServer {
            url: "https://pm.example.com:7777".into(),
            pin: pin.map(str::to_string),
            token: token.into(),
            saved_at: 1,
        };
        assert!(saved_server(&dir, "https://pm.example.com:7777").unwrap().is_none());
        save_server(&dir, entry(Some("sha256:abc"), "pm3_a")).unwrap();
        save_server(&dir, entry(None, "pm3_b")).unwrap();
        let e = saved_server(&dir, "https://PM.example.com:7777/").unwrap().unwrap();
        assert_eq!((e.token.as_str(), e.pin), ("pm3_b", None));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = servers_path(&dir);
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = saved_server(&dir, "https://pm.example.com:7777").unwrap_err().to_string();
            assert!(err.contains("readable by other users"), "{err}");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(forget_server(&dir, "https://pm.example.com:7777").unwrap());
        assert!(!forget_server(&dir, "https://pm.example.com:7777").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
