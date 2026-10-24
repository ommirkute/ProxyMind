//! Headless Chromium for rendering a *recorded* response offline.
//!
//! The browser never talks to the target. It navigates to the response's
//! URL (so the page has the right origin), the DevTools `Fetch` domain
//! answers that one navigation with the recorded status, headers and body,
//! and every other request the page makes (images, scripts, frames,
//! redirects) is failed before it leaves the browser. As a second line of
//! defence the browser is started with a proxy that doesn't exist and a
//! resolver that resolves nothing, so anything the `Fetch` domain can't see
//! (WebSockets, popups, service workers) fails too.
//!
//! Same-origin resources the caller already fetched (e.g. the page's own
//! scripts, through the policy gate) can be handed over too; they are
//! served the same way, still without the browser touching the network.
//!
//! What runs in the page is reported back: calls to a named JavaScript
//! binding (`Runtime.addBinding`) and JavaScript dialogs (`alert`,
//! `confirm`, `prompt`). The proof engine decides what that means.
//!
//! The DevTools protocol is spoken over a plain WebSocket using the frame
//! codec in [`pm_http::ws`]; no extra dependencies.

pub mod crawl;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::Instant;

/// Environment variable naming the Chromium/Chrome executable to use.
pub const ENV_CHROMIUM: &str = "PROXYMIND_CHROMIUM";
/// Set to `1` to start Chromium without its sandbox (needed in some
/// containers). Running as root on Linux implies it.
pub const ENV_NO_SANDBOX: &str = "PROXYMIND_CHROMIUM_NO_SANDBOX";

/// Longest string kept from the page (binding payloads, dialog messages, URLs).
const MAX_TEXT: usize = 500;
/// Most entries kept per list in a [`Report`].
const MAX_ITEMS: usize = 50;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not start the browser {path}: {reason}")]
    Launch { path: String, reason: String },
    #[error("browser I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("DevTools protocol: {0}")]
    Protocol(String),
    #[error("timed out {0}")]
    Timeout(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The response to show the browser.
#[derive(Debug, Clone)]
pub struct Document {
    /// URL the page is loaded under (`scheme://host[:port]/path?query`).
    pub url: String,
    pub status: u16,
    /// Headers as sent by the server, minus framing and compression headers
    /// (the body here is already decoded).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Other responses to serve when the page asks for exactly these URLs
    /// (fragment ignored); everything else is still blocked.
    pub resources: Vec<Resource>,
}

/// A response served for a subresource request.
#[derive(Debug, Clone)]
pub struct Resource {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RenderOptions {
    /// Name of the JavaScript function to expose (e.g. `pmProof`).
    pub binding: String,
    /// Hard limit for the whole render, browser start excluded.
    pub timeout: Duration,
    /// How long to keep watching after the load event (timers, late handlers).
    pub settle: Duration,
    /// Stop as soon as the binding is called with exactly this value, or a
    /// dialog's message contains it.
    pub stop_on: Option<String>,
    /// JavaScript run in every document before the page's own scripts
    /// (e.g. hooks that report what reaches dangerous sinks).
    pub init_script: Option<String>,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            binding: "pmProof".into(),
            timeout: Duration::from_secs(10),
            settle: Duration::from_millis(1000),
            stop_on: None,
            init_script: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    /// alert, confirm, prompt or beforeunload
    pub kind: String,
    pub message: String,
}

/// What happened while the page was shown. All strings come from the
/// target and are untrusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Arguments the page passed to the binding, in order.
    pub binding_calls: Vec<String>,
    pub dialogs: Vec<Dialog>,
    /// URLs the page tried to load; all were blocked.
    pub blocked: Vec<String>,
    /// Count of blocked requests (the list above is capped).
    pub blocked_total: usize,
    /// The recorded response was served for the navigation.
    pub served: bool,
    /// The load event fired.
    pub loaded: bool,
    pub navigation_error: Option<String>,
    /// Rendering stopped early because `stop_on` was seen.
    pub stopped_early: bool,
}

/// Finds a Chromium-family browser: `$PROXYMIND_CHROMIUM`, Playwright's
/// browsers, then the usual install locations and `PATH`.
pub fn find_chromium() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(ENV_CHROMIUM) {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    candidates().into_iter().find(|p| p.is_file())
}

fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let env_dir = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let home = env_dir("HOME").or_else(|| env_dir("USERPROFILE"));
    // Playwright's browser cache (also what this repo's UI tests install).
    let mut pw_roots: Vec<PathBuf> = vec![PathBuf::from("/opt/pw-browsers")];
    pw_roots.extend(env_dir("PLAYWRIGHT_BROWSERS_PATH"));
    if let Some(h) = &home {
        pw_roots.push(h.join(".cache/ms-playwright"));
        pw_roots.push(h.join("Library/Caches/ms-playwright"));
    }
    pw_roots.extend(env_dir("LOCALAPPDATA").map(|d| d.join("ms-playwright")));
    for root in &pw_roots {
        out.push(root.join("chromium"));
        let Ok(rd) = std::fs::read_dir(root) else { continue };
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("chromium-")))
            .collect();
        dirs.sort();
        for d in dirs.iter().rev() {
            for rel in [
                "chrome-linux/chrome",
                "chrome-linux64/chrome",
                "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
                "chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium",
                "chrome-win/chrome.exe",
                "chrome-win64/chrome.exe",
            ] {
                out.push(d.join(rel));
            }
        }
    }
    // macOS applications.
    for app in [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ] {
        out.push(PathBuf::from(app));
    }
    // Windows installs.
    for base in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"].iter().filter_map(|k| env_dir(k)) {
        out.push(base.join("Google/Chrome/Application/chrome.exe"));
        out.push(base.join("Chromium/Application/chrome.exe"));
        out.push(base.join("Microsoft/Edge/Application/msedge.exe"));
    }
    // PATH.
    let names = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"];
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for n in names {
                out.push(dir.join(n));
                out.push(dir.join(format!("{n}.exe")));
            }
        }
    }
    out
}

/// Renders `doc` in a fresh headless browser and reports what ran.
pub async fn render(chromium: &Path, doc: &Document, opts: &RenderOptions) -> Result<Report> {
    let browser = Browser::launch(chromium).await?;
    let result = tokio::time::timeout(opts.timeout + Duration::from_secs(120), drive(&browser, doc, opts))
        .await
        .unwrap_or(Err(Error::Timeout("rendering the page")));
    browser.shutdown().await;
    result
}

// ---------------------------------------------------- browser window --

/// Set to `1` to open the browser window headless (tests, CI, servers).
pub const ENV_WINDOW_HEADLESS: &str = "PROXYMIND_BROWSER_HEADLESS";

/// A browser window for manual testing, sent through ProxyMind's proxy.
#[derive(Debug, Clone)]
pub struct WindowOptions {
    /// The proxy, e.g. `127.0.0.1:8080`.
    pub proxy: String,
    /// Base64 SHA-256 of the interception CA's public key: the browser
    /// accepts certificates from that CA only, without installing it anywhere.
    pub ca_spki: Option<String>,
    /// Kept between launches (logins, cookies, settings).
    pub profile_dir: PathBuf,
    pub url: String,
}

/// Hosts Chromium calls by itself (not the site under test).
const CHROME_SERVICE_HOSTS: &[&str] = &[
    "android.clients.google.com",
    "clients1.google.com",
    "clients2.google.com",
    "clientservices.googleapis.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "content-autofill.googleapis.com",
    "edgedl.me.gvt1.com",
    "redirector.gvt1.com",
];

/// A running browser window. Dropping it leaves the browser open.
#[derive(Debug)]
pub struct Window {
    pub pid: Option<u32>,
    pub profile_dir: PathBuf,
}

/// Opens a Chromium window whose every request (loopback included) goes
/// through `opts.proxy`. Returns once the process has started.
pub async fn open_window(chromium: &Path, opts: &WindowOptions) -> Result<Window> {
    std::fs::create_dir_all(&opts.profile_dir)?;
    let headless = std::env::var(ENV_WINDOW_HEADLESS).is_ok_and(|v| v == "1");
    let no_sandbox = running_as_root() || std::env::var(ENV_NO_SANDBOX).is_ok_and(|v| v == "1");
    let mut cmd = std::process::Command::new(chromium);
    cmd.arg(format!("--user-data-dir={}", opts.profile_dir.display()))
        .arg(format!("--proxy-server=http://{}", opts.proxy))
        // Loopback targets go through the proxy too; Chromium's own service
        // calls (device registration, updates, safe browsing) don't, so they
        // stay out of the project.
        .arg(format!("--proxy-bypass-list=<-loopback>;{}", CHROME_SERVICE_HOSTS.join(";")))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            // Keep the browser's own background traffic out of the project.
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-domain-reliability",
            "--no-pings",
            // No browser sign-in or Google new-tab content of its own.
            "--allow-browser-signin=false",
            "--disable-search-engine-choice-screen",
            "--disable-features=Translate,OptimizationHints,MediaRouter,InterestFeedContentSuggestions,AutofillServerCommunication,NtpOneGoogleBar,NtpRealboxPedals,NtpModules,DiceWebSigninInterception",
            // No "unsupported command-line flag" bar for the certificate pin.
            "--test-type",
            "--password-store=basic",
            "--use-mock-keychain",
        ]);
    if let Some(spki) = &opts.ca_spki {
        cmd.arg(format!("--ignore-certificate-errors-spki-list={spki}"));
    }
    if headless {
        cmd.arg("--headless=new").arg("--remote-debugging-port=0");
    }
    if no_sandbox {
        cmd.arg("--no-sandbox");
    }
    cmd.arg(&opts.url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let mut child =
        cmd.spawn().map_err(|e| Error::Launch { path: chromium.display().to_string(), reason: e.to_string() })?;
    // A browser that dies at once (bad profile, missing libraries) is an error.
    tokio::time::sleep(Duration::from_millis(600)).await;
    if let Ok(Some(status)) = child.try_wait() {
        // Another window on the same profile hands the URL over and exits 0.
        if !status.success() {
            return Err(Error::Launch {
                path: chromium.display().to_string(),
                reason: format!("exited with {status}"),
            });
        }
    }
    let pid = Some(child.id());
    // Reap it in the background so it never lingers as a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(Window { pid, profile_dir: opts.profile_dir.clone() })
}

// ------------------------------------------------------------ process --

struct Browser {
    child: Child,
    dir: PathBuf,
    port: u16,
    ws_path: String,
}

enum LaunchError {
    /// The process exited, or never became ready, in time (often: no usable
    /// sandbox). The text includes the end of the browser's stderr.
    NotReady(String),
    Other(Error),
}

fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.split_whitespace().nth(2) == Some("0")))
        .unwrap_or(false)
}

fn temp_profile_dir() -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("proxymind-chromium-{}-{}-{n}", std::process::id(), pm_core::now_ms()))
}

impl Browser {
    async fn launch(path: &Path) -> Result<Self> {
        let no_sandbox = running_as_root() || std::env::var(ENV_NO_SANDBOX).is_ok_and(|v| v == "1");
        let fail = |reason| Err(Error::Launch { path: path.display().to_string(), reason });
        if no_sandbox {
            return match Self::launch_once(path, true, Duration::from_secs(45)).await {
                Ok(b) => Ok(b),
                Err(LaunchError::NotReady(r)) => fail(r),
                Err(LaunchError::Other(e)) => Err(e),
            };
        }
        match Self::launch_once(path, false, Duration::from_secs(20)).await {
            Ok(b) => Ok(b),
            Err(LaunchError::NotReady(first)) => {
                tracing::warn!("browser did not start with its sandbox ({first}); retrying without it");
                match Self::launch_once(path, true, Duration::from_secs(45)).await {
                    Ok(b) => Ok(b),
                    Err(LaunchError::NotReady(r)) => fail(format!("{r}; with the sandbox: {first}")),
                    Err(LaunchError::Other(e)) => Err(e),
                }
            }
            Err(LaunchError::Other(e)) => Err(e),
        }
    }

    async fn launch_once(path: &Path, no_sandbox: bool, wait: Duration) -> std::result::Result<Self, LaunchError> {
        let dir = temp_profile_dir();
        std::fs::create_dir_all(&dir).map_err(|e| LaunchError::Other(e.into()))?;
        let mut cmd = Command::new(path);
        cmd.arg("--headless=new")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", dir.display()))
            // Nothing may leave the browser: a proxy that refuses every
            // connection (loopback included) and a resolver that finds nothing.
            .arg("--proxy-server=http://127.0.0.1:1")
            .arg("--proxy-bypass-list=<-loopback>")
            .arg("--host-resolver-rules=MAP * ~NOTFOUND")
            .arg("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-sync",
                "--disable-client-side-phishing-detection",
                "--disable-features=Translate,OptimizationHints,MediaRouter,InterestFeedContentSuggestions",
                "--metrics-recording-only",
                "--mute-audio",
                "--disable-gpu",
                "--hide-scrollbars",
                "--window-size=1280,800",
                // Never wait on an OS keyring or keychain prompt.
                "--password-store=basic",
                "--use-mock-keychain",
            ]);
        if no_sandbox {
            cmd.arg("--no-sandbox");
        }
        let log = dir.join("stderr.log");
        let stderr = std::fs::File::create(&log).map(Stdio::from).unwrap_or_else(|_| Stdio::null());
        cmd.arg("about:blank").stdin(Stdio::null()).stdout(Stdio::null()).stderr(stderr).kill_on_drop(true);
        let child = cmd.spawn().map_err(|e| {
            LaunchError::Other(Error::Launch { path: path.display().to_string(), reason: e.to_string() })
        })?;
        let mut b = Browser { child, dir, port: 0, ws_path: String::new() };
        let deadline = Instant::now() + wait;
        let stderr_tail = || {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let tail = lines[lines.len().saturating_sub(3)..].join(" | ");
            if tail.is_empty() { String::new() } else { format!("; stderr: {}", clip(&tail)) }
        };
        let port_file = b.dir.join("DevToolsActivePort");
        loop {
            if let Ok(s) = std::fs::read_to_string(&port_file) {
                let mut lines = s.lines();
                if let (Some(Ok(port)), Some(p)) = (lines.next().map(str::parse::<u16>), lines.next())
                    && p.starts_with('/')
                {
                    b.port = port;
                    b.ws_path = p.to_string();
                    return Ok(b);
                }
            }
            if let Ok(Some(status)) = b.child.try_wait() {
                let why = format!("exited with {status}{}", stderr_tail());
                b.shutdown().await;
                return Err(LaunchError::NotReady(why));
            }
            if Instant::now() >= deadline {
                let why = format!("not ready after {} s{}", wait.as_secs(), stderr_tail());
                b.shutdown().await;
                return Err(LaunchError::NotReady(why));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
        // The profile directory may stay locked for a moment after exit (Windows).
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.dir).is_ok() || !self.dir.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

// ---------------------------------------------------------------- CDP --

struct Cdp {
    stream: TcpStream,
    decoder: pm_http::ws::Decoder,
    inbox: VecDeque<Value>,
    next_id: u64,
    mask: u32,
}

impl Cdp {
    async fn connect(port: u16, path: &str) -> Result<Self> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let key = pm_core::base64(&pm_core::now_ms().to_be_bytes().repeat(2));
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        let end = loop {
            if let Ok(Some(end)) = pm_http::find_head_end(&buf) {
                break end;
            }
            if buf.len() > 64 * 1024 {
                return Err(Error::Protocol("handshake response too large".into()));
            }
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut chunk))
                .await
                .map_err(|_| Error::Timeout("connecting to the browser"))??;
            if n == 0 {
                return Err(Error::Protocol("browser closed the connection during the handshake".into()));
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = pm_http::parse_response_head(&buf[..end]).map_err(|e| Error::Protocol(e.to_string()))?;
        if head.status != 101 {
            return Err(Error::Protocol(format!("WebSocket handshake refused with {}", head.status)));
        }
        let mut cdp = Cdp {
            stream,
            decoder: pm_http::ws::Decoder::new(64 * 1024 * 1024),
            inbox: VecDeque::new(),
            next_id: 1,
            mask: 0x9e37_79b9 ^ (pm_core::now_ms() as u32),
        };
        let rest = buf[end..].to_vec();
        cdp.absorb(&rest).await?;
        Ok(cdp)
    }

    async fn send(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        // xorshift: any mask works for a local connection; vary it anyway.
        self.mask ^= self.mask << 13;
        self.mask ^= self.mask >> 17;
        self.mask ^= self.mask << 5;
        let frame =
            pm_http::ws::encode_frame(pm_http::ws::TEXT, msg.to_string().as_bytes(), Some(self.mask.to_be_bytes()));
        self.stream.write_all(&frame).await?;
        Ok(id)
    }

    /// Sends a command and waits for its result; events seen meanwhile are queued.
    async fn call(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<Value> {
        let id = self.send(method, params, session).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut skipped = VecDeque::new();
        let result = loop {
            let Some(msg) = self.next(deadline).await? else {
                break Err(Error::Timeout("waiting for the browser to answer"));
            };
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                break match msg.get("error") {
                    Some(e) => Err(Error::Protocol(format!("{method}: {}", e["message"].as_str().unwrap_or("error")))),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
            }
            skipped.push_back(msg);
        };
        // Put the events back in order, ahead of anything read later.
        while let Some(m) = skipped.pop_back() {
            self.inbox.push_front(m);
        }
        result
    }

    /// Next message, or `None` at the deadline.
    async fn next(&mut self, deadline: Instant) -> Result<Option<Value>> {
        loop {
            if let Some(m) = self.inbox.pop_front() {
                return Ok(Some(m));
            }
            let mut chunk = vec![0u8; 64 * 1024];
            let n = match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
                Err(_) => return Ok(None),
                Ok(r) => r?,
            };
            if n == 0 {
                return Err(Error::Protocol("browser closed the DevTools connection".into()));
            }
            self.absorb(&chunk[..n]).await?;
        }
    }

    async fn absorb(&mut self, bytes: &[u8]) -> Result<()> {
        let mut msgs = Vec::new();
        self.decoder.feed(bytes, &mut msgs).map_err(|e| Error::Protocol(e.to_string()))?;
        for m in msgs {
            match m.opcode {
                pm_http::ws::TEXT => match serde_json::from_slice::<Value>(&m.payload) {
                    Ok(v) => self.inbox.push_back(v),
                    Err(e) => return Err(Error::Protocol(format!("bad JSON from the browser: {e}"))),
                },
                pm_http::ws::PING => {
                    let frame = pm_http::ws::encode_frame(pm_http::ws::PONG, &m.payload, Some([1, 2, 3, 4]));
                    self.stream.write_all(&frame).await?;
                }
                pm_http::ws::CLOSE => return Err(Error::Protocol("browser closed the DevTools connection".into())),
                _ => {}
            }
        }
        Ok(())
    }
}

fn clip(s: &str) -> String {
    if s.len() <= MAX_TEXT {
        return s.to_string();
    }
    let mut end = MAX_TEXT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Headers the browser must not see: the body handed over is already
/// de-chunked and decompressed.
fn skip_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length" | "transfer-encoding" | "content-encoding" | "connection" | "keep-alive"
    )
}

async fn drive(browser: &Browser, doc: &Document, opts: &RenderOptions) -> Result<Report> {
    // A freshly started browser on a busy machine can be slow to answer
    // its first connection; try a few times.
    let mut attempt = 0;
    let mut cdp = loop {
        match Cdp::connect(browser.port, &browser.ws_path).await {
            Ok(c) => break c,
            Err(e) if attempt < 2 => {
                tracing::warn!("DevTools connection failed ({e}); retrying");
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let target = cdp.call("Target.createTarget", json!({ "url": "about:blank" }), None).await?;
    let target_id = target["targetId"].as_str().ok_or_else(|| Error::Protocol("no targetId".into()))?.to_string();
    let attached = cdp.call("Target.attachToTarget", json!({ "targetId": target_id, "flatten": true }), None).await?;
    let session = attached["sessionId"].as_str().ok_or_else(|| Error::Protocol("no sessionId".into()))?.to_string();
    let s = Some(session.as_str());
    cdp.call("Fetch.enable", json!({ "patterns": [{ "urlPattern": "*" }] }), s).await?;
    cdp.call("Page.enable", json!({}), s).await?;
    cdp.call("Runtime.enable", json!({}), s).await?;
    cdp.call("Runtime.addBinding", json!({ "name": opts.binding }), s).await?;
    if let Some(js) = &opts.init_script {
        cdp.call("Page.addScriptToEvaluateOnNewDocument", json!({ "source": js }), s).await?;
    }
    let nav_id = cdp.send("Page.navigate", json!({ "url": doc.url }), s).await?;

    let headers: Vec<Value> =
        doc.headers.iter().filter(|(n, _)| !skip_header(n)).map(|(n, v)| json!({ "name": n, "value": v })).collect();
    let body = pm_core::base64(&doc.body);
    let mut report = Report::default();
    let mut deadline = Instant::now() + opts.timeout;
    while let Some(msg) = cdp.next(deadline).await? {
        if msg.get("id").and_then(Value::as_u64) == Some(nav_id) {
            let err = msg["error"]["message"].as_str().or_else(|| msg["result"]["errorText"].as_str());
            if let Some(e) = err {
                report.navigation_error = Some(clip(e));
            }
            continue;
        }
        if msg.get("sessionId").and_then(Value::as_str) != Some(session.as_str()) {
            continue;
        }
        let p = &msg["params"];
        match msg["method"].as_str().unwrap_or("") {
            "Fetch.requestPaused" => {
                let request_id = p["requestId"].as_str().unwrap_or_default().to_string();
                let main_document =
                    p["resourceType"] == "Document" && p["frameId"].as_str() == Some(target_id.as_str());
                if main_document && !report.served {
                    report.served = true;
                    cdp.send(
                        "Fetch.fulfillRequest",
                        json!({ "requestId": request_id, "responseCode": doc.status,
                                "responseHeaders": headers, "body": body }),
                        s,
                    )
                    .await?;
                } else if let Some(r) = {
                    let url = p["request"]["url"].as_str().unwrap_or("");
                    let url = url.split('#').next().unwrap_or(url);
                    doc.resources.iter().find(|r| r.url.split('#').next() == Some(url))
                } {
                    let headers: Vec<Value> = r
                        .headers
                        .iter()
                        .filter(|(n, _)| !skip_header(n))
                        .map(|(n, v)| json!({ "name": n, "value": v }))
                        .collect();
                    cdp.send(
                        "Fetch.fulfillRequest",
                        json!({ "requestId": request_id, "responseCode": r.status,
                                "responseHeaders": headers, "body": pm_core::base64(&r.body) }),
                        s,
                    )
                    .await?;
                } else {
                    report.blocked_total += 1;
                    if report.blocked.len() < MAX_ITEMS {
                        report.blocked.push(clip(p["request"]["url"].as_str().unwrap_or("")));
                    }
                    cdp.send(
                        "Fetch.failRequest",
                        json!({ "requestId": request_id, "errorReason": "BlockedByClient" }),
                        s,
                    )
                    .await?;
                }
            }
            "Runtime.bindingCalled" if p["name"].as_str() == Some(opts.binding.as_str()) => {
                let payload = p["payload"].as_str().unwrap_or("");
                if report.binding_calls.len() < MAX_ITEMS {
                    report.binding_calls.push(clip(payload));
                }
                if opts.stop_on.as_deref() == Some(payload) {
                    report.stopped_early = true;
                    break;
                }
            }
            "Page.javascriptDialogOpening" => {
                let message = p["message"].as_str().unwrap_or("");
                if report.dialogs.len() < MAX_ITEMS {
                    report
                        .dialogs
                        .push(Dialog { kind: clip(p["type"].as_str().unwrap_or("")), message: clip(message) });
                }
                cdp.send("Page.handleJavaScriptDialog", json!({ "accept": true }), s).await?;
                if opts.stop_on.as_deref().is_some_and(|t| message.contains(t)) {
                    report.stopped_early = true;
                    break;
                }
            }
            "Page.loadEventFired" if !report.loaded => {
                report.loaded = true;
                deadline = deadline.min(Instant::now() + opts.settle);
            }
            _ => {}
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_on_char_boundaries() {
        let s = "é".repeat(400);
        let c = clip(&s);
        assert!(c.len() <= MAX_TEXT + '…'.len_utf8());
        assert!(c.ends_with('…'));
        assert_eq!(clip("short"), "short");
    }

    #[test]
    fn framing_headers_are_dropped() {
        assert!(skip_header("Content-Length") && skip_header("transfer-encoding") && skip_header("Content-Encoding"));
        assert!(!skip_header("Content-Type") && !skip_header("Content-Security-Policy"));
    }

    #[test]
    fn candidates_include_env_style_locations() {
        assert!(candidates().iter().any(|p| p.ends_with("chromium")));
    }
}
