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
}

/// Creates a random API token.
pub fn new_token() -> String {
    // Two OAST-style tokens give 160 bits of mixed state; plenty for a
    // local, per-install secret.
    format!("{}{}", pm_service::pm_oast::new_token(), pm_service::pm_oast::new_token())
}

/// Loads the token from `path`, creating it (mode 0600) if missing.
pub fn load_or_create_token(path: &std::path::Path) -> anyhow::Result<String> {
    if let Ok(t) = std::fs::read_to_string(path) {
        let t = t.trim().to_string();
        if t.len() >= 32 {
            return Ok(t);
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let t = new_token();
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
