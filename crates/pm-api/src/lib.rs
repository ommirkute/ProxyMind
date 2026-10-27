//! REST API and live event stream for the UI (and any other client).
//!
//! Every route calls `pm-service`, so the same rules apply as for agents
//! (ADR-0005). The API acts as one human user, set when it starts.
//!
//! Security (it runs on the tester's machine next to client data):
//! - binds to loopback by default; refuses requests whose `Host` isn't
//!   localhost (stops DNS-rebinding attacks from web pages);
//! - every request needs the per-install token, as `Authorization: Bearer`
//!   or the `pm_token` cookie set by `/auth?token=…`;
//! - requests that change anything must carry `X-ProxyMind: 1`, which a
//!   cross-site form or image can't send.

mod routes;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use pm_service::Service;
use pm_service::pm_policy::Actor;

mod assets {
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));
}

#[derive(Clone)]
pub struct AppState {
    pub service: Arc<Service>,
    /// The human the UI acts as.
    pub actor: Actor,
    pub token: Arc<String>,
    pub project: Arc<String>,
    /// The built-in assistant (acts as agent:assistant, not as `actor`).
    pub assistant: Arc<pm_assistant::Assistant>,
    /// How browsers connect: the proxy address and the CA to trust.
    pub setup: Arc<ProxySetup>,
}

/// What the Proxy setup page shows.
#[derive(Debug, Clone, Default)]
pub struct ProxySetup {
    /// e.g. 127.0.0.1:8080, when this process runs the proxy.
    pub proxy: Option<String>,
    /// The CA certificate (PEM) browsers must trust for HTTPS.
    pub ca_pem: Option<String>,
}

impl ProxySetup {
    /// SHA-256 of the CA certificate (DER), as browsers show it (`AB:CD:…`).
    pub fn ca_fingerprint(&self) -> Option<String> {
        let pem = self.ca_pem.as_deref()?;
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("");
        let der = pm_service::pm_tools::codec::base64_decode(b64.trim(), false).ok()?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &der);
        Some(digest.as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
    }
}

impl AppState {
    pub fn new(service: Arc<Service>, actor: Actor, token: String, project: String) -> anyhow::Result<Self> {
        let assistant = Arc::new(pm_assistant::Assistant::new(service.clone()).map_err(|e| anyhow::anyhow!("{e}"))?);
        Ok(Self {
            service,
            actor,
            token: Arc::new(token),
            project: Arc::new(project),
            assistant,
            setup: Arc::new(ProxySetup::default()),
        })
    }

    /// Adds the proxy address and CA for the Proxy setup page.
    pub fn with_setup(mut self, setup: ProxySetup) -> Self {
        self.setup = Arc::new(setup);
        self
    }
}

/// Marks tokens made from the system's secure random source. Token files
/// from older versions (made from the clock and process id, so guessable)
/// lack it and are replaced.
const TOKEN_PREFIX: &str = "pm2_";

/// Creates a random API token: 256 bits from the system's secure random source.
pub fn new_token() -> anyhow::Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 32];
    SystemRandom::new().fill(&mut b).map_err(|_| anyhow::anyhow!("no secure randomness from the system"))?;
    Ok(format!("{TOKEN_PREFIX}{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

/// Loads the token from `path`, creating it (mode 0600) if missing or made
/// by an older version.
pub fn load_or_create_token(path: &std::path::Path) -> anyhow::Result<String> {
    if let Ok(t) = std::fs::read_to_string(path) {
        let t = t.trim().to_string();
        if t.starts_with(TOKEN_PREFIX) && t.len() >= TOKEN_PREFIX.len() + 64 {
            return Ok(t);
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let t = new_token()?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(t.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, &t)?;
    Ok(t)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .nest("/api/v1", routes::api())
        .route("/auth", axum::routing::get(routes::auth))
        .fallback(static_asset)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

fn host_is_local(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else { return false };
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

fn token_ok(headers: &HeaderMap, token: &str) -> bool {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| constant_eq(t.as_bytes(), token.as_bytes()));
    let cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().strip_prefix("pm_token="))
        .any(|t| constant_eq(t.as_bytes(), token.as_bytes()));
    bearer || cookie
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if !host_is_local(headers) {
        return (StatusCode::FORBIDDEN, "ProxyMind only answers requests addressed to localhost").into_response();
    }
    let path = req.uri().path();
    let is_api = path.starts_with("/api/");
    if is_api && !token_ok(headers, &st.token) {
        return (StatusCode::UNAUTHORIZED, "missing or wrong ProxyMind token").into_response();
    }
    let changes_state = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if is_api && changes_state && headers.get("x-proxymind").and_then(|v| v.to_str().ok()) != Some("1") {
        return (StatusCode::FORBIDDEN, "state-changing requests need the X-ProxyMind: 1 header").into_response();
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-content-type-options", "nosniff".parse().expect("static"));
    h.insert("referrer-policy", "no-referrer".parse().expect("static"));
    h.insert("x-frame-options", "DENY".parse().expect("static"));
    h.insert(
        "content-security-policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .expect("static"),
    );
    resp
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn static_asset(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let found = assets::ASSETS.iter().find(|(n, _)| *n == path);
    // Unknown paths get index.html so client-side routes work.
    let (name, bytes) = match found {
        Some(f) => *f,
        None => match assets::ASSETS.iter().find(|(n, _)| *n == "index.html") {
            Some(f) => *f,
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let cache = if name == "index.html" { "no-store" } else { "public, max-age=31536000, immutable" };
    Response::builder()
        .header(header::CONTENT_TYPE, content_type(name))
        .header(header::CACHE_CONTROL, cache)
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_only() {
        let mut h = HeaderMap::new();
        for (host, ok) in [
            ("127.0.0.1:7777", true),
            ("localhost:7777", true),
            ("[::1]:7777", true),
            ("evil.com", false),
            ("127.0.0.1.evil.com:7777", false),
            ("localhost.evil.com", false),
        ] {
            h.insert(header::HOST, host.parse().unwrap());
            assert_eq!(host_is_local(&h), ok, "{host}");
        }
    }

    #[test]
    fn token_checks() {
        let mut h = HeaderMap::new();
        assert!(!token_ok(&h, "secret"));
        h.insert(header::COOKIE, "a=b; pm_token=secret".parse().unwrap());
        assert!(token_ok(&h, "secret"));
        h.insert(header::COOKIE, "pm_token=secreT".parse().unwrap());
        assert!(!token_ok(&h, "secret"));
        h.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(token_ok(&h, "secret"));
    }
}
