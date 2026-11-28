//! The network side of OIDC sign-in (ADR-0022 step 8): fetching the discovery document and the key set, and the token
//! request. Everything that *decides* (what a document or a token must look like) is `pm_accounts::oidc` and takes bytes;
//! this file only moves them, so the checks stay testable without a network.
//!
//! * **TLS** is `pm_replay::Sender` with verification on: rustls with the public web PKI roots. It never uses the
//!   interception CA and there is no switch to turn verification off. `https` is required for every endpoint, except
//!   `http` to a loopback host (tests, a provider on this machine); the address check below also refuses link-local
//!   addresses (cloud metadata) and, for plain http, anything but loopback, at connect time on the resolved addresses.
//! * **Limits:** every fetch has a total deadline (15 s) and reads at most 512 KiB (head and body). Redirects are not
//!   followed. The response must be `200`.
//! * **Caching:** the discovery document and the keys are cached for an hour each. A token signed by a `kid` we do not
//!   have makes the key set be fetched again, **at most once per 30 seconds** per provider (rotation), never more, so a
//!   stream of forged tokens cannot make this server hammer a provider. Keys come only from the `jwks_uri` of the
//!   discovery document: nothing in a token (`jku`, `x5u`, `jwk`) is ever fetched or used.
//! * **Secrets:** the client secret, the code and the PKCE verifier are in the request and nowhere else: not in the
//!   errors this file makes, not in logs.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pm_accounts::oidc::OidcProvider;
use pm_accounts::oidc::discovery::{self, Discovery, TokenAuth};
use pm_accounts::oidc::jwt::{self, Expect, IdClaims, JwkKey, JwtError};
use pm_replay::{Endpoint, Sender};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::AppState;

/// How long a discovery document or a key set is trusted.
pub(crate) const CACHE_TTL: i64 = 3600;
/// The shortest time between two fetches of a provider's key set (the first included).
pub(crate) const JWKS_MIN_INTERVAL: i64 = 30;
const MAX_RESPONSE: usize = 512 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);
const MAX_ID_TOKEN: usize = jwt::MAX_TOKEN_BYTES;

/// Why a provider exchange failed. The messages hold no secret and no token content.
#[derive(Debug)]
pub(crate) enum FlowError {
    /// Could not fetch (connect, TLS, timeout, size, a status other than 200).
    Fetch(String),
    /// The discovery document or key set is not acceptable.
    Document(&'static str),
    /// The token endpoint refused or answered nonsense.
    Token(String),
    /// The ID token is not valid.
    IdToken(JwtError),
}

impl FlowError {
    /// A fixed phrase for the security log.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            FlowError::Fetch(_) => "provider unreachable",
            FlowError::Document(_) => "provider document not acceptable",
            FlowError::Token(_) => "token request failed",
            FlowError::IdToken(e) => e.reason(),
        }
    }

    /// What the browser is told (a code the UI knows; nothing from the provider).
    pub(crate) fn code(&self) -> &'static str {
        match self {
            FlowError::Fetch(_) | FlowError::Document(_) => "provider_unreachable",
            FlowError::Token(_) => "provider_error",
            FlowError::IdToken(JwtError::Claim("acr not accepted" | "amr not accepted")) => "assurance_not_met",
            FlowError::IdToken(_) => "invalid_token",
        }
    }

    /// For an administrator's test: the details.
    pub(crate) fn detail(&self) -> String {
        match self {
            FlowError::Fetch(m) | FlowError::Token(m) => m.clone(),
            FlowError::Document(m) => (*m).to_string(),
            FlowError::IdToken(e) => e.reason().to_string(),
        }
    }
}

struct Entry {
    issuer: String,
    discovery: Discovery,
    discovered_at: i64,
    jwks: Option<Vec<JwkKey>>,
    /// When the key set was last fetched, or a refetch was last claimed.
    jwks_at: i64,
}

/// What the token request carries besides the client's credentials.
#[derive(Clone, Copy)]
pub(crate) struct CodeGrant<'a> {
    /// The authorization code from the callback.
    pub code: &'a str,
    /// The PKCE verifier kept for this sign-in.
    pub verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// What the server remembers about providers, and the one HTTP client.
#[derive(Default)]
pub(crate) struct OidcRuntime {
    sender: OnceLock<Arc<Sender>>,
    cache: Mutex<HashMap<String, Entry>>,
}

/// Addresses we will connect to: not unspecified, multicast, broadcast or link-local (cloud metadata); and for plain
/// http, only loopback.
pub(crate) fn address_ok(ips: &[IpAddr], plain: bool) -> Result<(), String> {
    for ip in ips {
        let ip = ip.to_canonical();
        if plain && !ip.is_loopback() {
            return Err("plain http is only allowed to a loopback address".into());
        }
        let bad = ip.is_unspecified()
            || ip.is_multicast()
            || match ip {
                IpAddr::V4(a) => a.is_link_local() || a.is_broadcast(),
                IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
            };
        if bad {
            return Err("refused to connect to that address".into());
        }
    }
    Ok(())
}

impl OidcRuntime {
    fn sender(&self, st: &AppState) -> Result<Arc<Sender>, FlowError> {
        if let Some(s) = self.sender.get() {
            return Ok(s.clone());
        }
        // Verification is always on: there is no insecure option.
        let s = Sender::new(true)
            .map_err(|e| FlowError::Fetch(format!("cannot set up TLS: {e:#}")))?
            .with_network(st.service.network().clone())
            .with_timeouts(Duration::from_secs(8), Duration::from_secs(15));
        Ok(self.sender.get_or_init(|| Arc::new(s)).clone())
    }

    /// One request, bounded in time and size. Returns the status and the body.
    async fn request(
        &self,
        st: &AppState,
        method: &'static str,
        url: &Url,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), FlowError> {
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(a)) => a.to_string(),
            Some(url::Host::Ipv6(a)) => a.to_string(),
            None => return Err(FlowError::Fetch("the address has no host".into())),
        };
        let port = url.port_or_known_default().unwrap_or(443);
        let sender = self.sender(st)?;
        let ep = Endpoint::new(url.scheme(), &host, port);
        let plain = url.scheme() == "http";
        let check = move |ips: &[IpAddr]| address_ok(ips, plain);
        let mut path = url.path().to_string();
        if let Some(q) = url.query() {
            path.push('?');
            path.push_str(q);
        }
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ProxyMind/{}\r\nAccept: application/json\r\n\
             Connection: close\r\n",
            pm_core::authority(url.scheme(), &host, port),
            env!("CARGO_PKG_VERSION")
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = &body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        let mut wire = req.into_bytes();
        if let Some(b) = body {
            wire.extend_from_slice(&b);
        }
        let work = async {
            let mut io = sender.connect(&ep, Some(&check)).await.map_err(|e| FlowError::Fetch(format!("{e:#}")))?;
            io.write_all(&wire).await.map_err(|e| FlowError::Fetch(format!("write failed: {e}")))?;
            io.flush().await.map_err(|e| FlowError::Fetch(format!("write failed: {e}")))?;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = io.read(&mut chunk).await.map_err(|e| FlowError::Fetch(format!("read failed: {e}")))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE {
                    return Err(FlowError::Fetch("the response is too large".into()));
                }
                if complete(&buf, method) {
                    break;
                }
            }
            parse_response(&buf, method)
        };
        tokio::time::timeout(DEADLINE, work).await.map_err(|_| FlowError::Fetch("timed out".into()))?
    }

    async fn get_json(&self, st: &AppState, url: &Url) -> Result<Vec<u8>, FlowError> {
        let (status, body) = self.request(st, "GET", url, &[], None).await?;
        if status != 200 {
            return Err(FlowError::Fetch(format!("{} answered {status}", url.host_str().unwrap_or("the provider"))));
        }
        Ok(body)
    }

    // ---- discovery and keys ------------------------------------------------------------------------------------

    /// The provider's discovery document: cached for an hour, fetched fresh with `force`.
    pub(crate) async fn discovery(
        &self,
        st: &AppState,
        now: i64,
        p: &OidcProvider,
        force: bool,
    ) -> Result<Discovery, FlowError> {
        if !force && let Some(e) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&p.id) {
            let age = now.saturating_sub(e.discovered_at);
            if e.issuer == p.issuer && (0..CACHE_TTL).contains(&age) {
                return Ok(e.discovery.clone());
            }
        }
        let url = discovery::check_endpoint(&discovery::discovery_url(&p.issuer))
            .map_err(|_| FlowError::Document("the issuer is not a usable address"))?;
        let body = self.get_json(st, &url).await?;
        let d = discovery::parse_discovery(&body, &p.issuer).map_err(FlowError::Document)?;
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        // A document fetched again keeps the keys already held (they have their own clock).
        let keep = cache.remove(&p.id).filter(|e| e.issuer == p.issuer && e.discovery.jwks_uri == d.jwks_uri);
        cache.insert(
            p.id.clone(),
            Entry {
                issuer: p.issuer.clone(),
                discovery: d.clone(),
                discovered_at: now,
                jwks: keep.as_ref().and_then(|e| e.jwks.clone()),
                jwks_at: keep.map_or(0, |e| e.jwks_at),
            },
        );
        Ok(d)
    }

    /// Forgets what is held about a provider (after it was changed or deleted).
    pub(crate) fn forget(&self, provider_id: &str) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).remove(provider_id);
    }

    async fn fetch_jwks(
        &self,
        st: &AppState,
        now: i64,
        p: &OidcProvider,
        d: &Discovery,
    ) -> Result<Vec<JwkKey>, FlowError> {
        let url = discovery::check_endpoint(&d.jwks_uri)
            .map_err(|_| FlowError::Document("the jwks_uri is not acceptable"))?;
        let body = self.get_json(st, &url).await?;
        let keys = jwt::parse_jwks(&body).map_err(|_| FlowError::Document("the key set is not valid"))?;
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = cache.get_mut(&p.id) {
            e.jwks = Some(keys.clone());
            e.jwks_at = now;
        }
        Ok(keys)
    }

    /// The keys to verify with: the cached set while it is fresh, else fetched.
    async fn keys(&self, st: &AppState, now: i64, p: &OidcProvider, d: &Discovery) -> Result<Vec<JwkKey>, FlowError> {
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(e) = cache.get(&p.id)
                && let Some(keys) = &e.jwks
                && (0..CACHE_TTL).contains(&now.saturating_sub(e.jwks_at))
            {
                return Ok(keys.clone());
            }
        }
        self.claim_fetch(&p.id, now, true);
        self.fetch_jwks(st, now, p, d).await
    }

    /// Marks a key-set fetch as taking place now. With `force` it always succeeds (the set is missing or stale); without,
    /// only when the last fetch is at least [`JWKS_MIN_INTERVAL`] old. The check and the mark are one step, so
    /// concurrent callers cannot both refetch.
    fn claim_fetch(&self, provider_id: &str, now: i64, force: bool) -> bool {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let Some(e) = cache.get_mut(provider_id) else { return false };
        let age = now.saturating_sub(e.jwks_at);
        if !force && (0..JWKS_MIN_INTERVAL).contains(&age) {
            return false;
        }
        e.jwks_at = now;
        true
    }

    /// Verifies an ID token. A `kid` we do not know refetches the key set once (rate limited) and tries again.
    pub(crate) async fn verify(
        &self,
        st: &AppState,
        now: i64,
        p: &OidcProvider,
        d: &Discovery,
        token: &str,
        expect: &Expect<'_>,
    ) -> Result<IdClaims, FlowError> {
        let keys = self.keys(st, now, p, d).await?;
        match jwt::verify_id_token(token, &keys, expect) {
            Err(JwtError::UnknownKey) => {
                if !self.claim_fetch(&p.id, now, false) {
                    return Err(FlowError::IdToken(JwtError::UnknownKey));
                }
                let keys = self.fetch_jwks(st, now, p, d).await?;
                jwt::verify_id_token(token, &keys, expect).map_err(FlowError::IdToken)
            }
            other => other.map_err(FlowError::IdToken),
        }
    }

    /// Fetches the key set now and reports how many usable keys it has (the administrator's test).
    pub(crate) async fn test_keys(
        &self,
        st: &AppState,
        now: i64,
        p: &OidcProvider,
        d: &Discovery,
    ) -> Result<Vec<JwkKey>, FlowError> {
        self.claim_fetch(&p.id, now, true);
        self.fetch_jwks(st, now, p, d).await
    }

    // ---- the token request -------------------------------------------------------------------------------------

    /// Exchanges the authorization `code` (with the PKCE verifier) for the ID token. The client authenticates with its
    /// secret as the provider's discovery document says (Basic or in the form), or sends only its id when it has none.
    pub(crate) async fn exchange(
        &self,
        st: &AppState,
        p: &OidcProvider,
        d: &Discovery,
        secret: Option<&str>,
        grant: &CodeGrant<'_>,
    ) -> Result<String, FlowError> {
        let CodeGrant { code, verifier, redirect_uri } = *grant;
        let url = discovery::check_endpoint(&d.token_endpoint)
            .map_err(|_| FlowError::Document("the token endpoint is not acceptable"))?;
        // The form is built in a block: the serializer is not `Send`, so it must not live across an await.
        let (form, headers) = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", code)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("code_verifier", verifier);
            let mut headers = vec![("Content-Type", "application/x-www-form-urlencoded".to_string())];
            match (secret, d.token_auth) {
                (Some(s), TokenAuth::Basic) => {
                    let enc = |v: &str| url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
                    let creds = format!("{}:{}", enc(&p.client_id), enc(s));
                    headers.push(("Authorization", format!("Basic {}", pm_core::base64(creds.as_bytes()))));
                }
                (Some(s), TokenAuth::Post) => {
                    form.append_pair("client_id", &p.client_id).append_pair("client_secret", s);
                }
                // A public client names itself.
                (None, _) => {
                    form.append_pair("client_id", &p.client_id);
                }
            }
            (form.finish(), headers)
        };
        let (status, body) = self.request(st, "POST", &url, &headers, Some(form.into_bytes())).await?;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        if status != 200 {
            // Only the standard error code, when it is a short plain word.
            let code = json
                .get("error")
                .and_then(|e| e.as_str())
                .filter(|e| e.len() <= 40 && e.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
                .unwrap_or("no error code");
            return Err(FlowError::Token(format!("the token endpoint answered {status} ({code})")));
        }
        let token = json
            .get("id_token")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty() && t.len() <= MAX_ID_TOKEN)
            .ok_or_else(|| FlowError::Token("the token endpoint sent no id_token".into()))?;
        Ok(token.to_string())
    }
}

// ---- reading a response ----------------------------------------------------------------------------------------

/// Is the whole message in `buf`? (Head, and a body of the length or chunking it announces.)
fn complete(buf: &[u8], method: &str) -> bool {
    let Ok(Some(end)) = pm_http::find_head_end(buf) else { return false };
    let Ok(head) = pm_http::parse_response_head(&buf[..end]) else { return true };
    match head.body_kind(method) {
        Ok(pm_http::BodyKind::None) => true,
        Ok(pm_http::BodyKind::ContentLength(n)) => u64::try_from(buf.len() - end).is_ok_and(|have| have >= n),
        Ok(pm_http::BodyKind::Chunked) => pm_http::decode_chunked(&buf[end..]).is_some(),
        _ => false,
    }
}

fn parse_response(buf: &[u8], method: &str) -> Result<(u16, Vec<u8>), FlowError> {
    let bad = |m: &str| FlowError::Fetch(m.to_string());
    let end = pm_http::find_head_end(buf).ok().flatten().ok_or_else(|| bad("the response has no head"))?;
    let head = pm_http::parse_response_head(&buf[..end]).map_err(|_| bad("the response is not HTTP"))?;
    let body = &buf[end..];
    let body = match head.body_kind(method).map_err(|_| bad("the response framing is invalid"))? {
        pm_http::BodyKind::None => Vec::new(),
        pm_http::BodyKind::ContentLength(n) => {
            let n = usize::try_from(n).map_err(|_| bad("the response is too large"))?;
            if body.len() < n {
                return Err(bad("the response ended early"));
            }
            body[..n].to_vec()
        }
        pm_http::BodyKind::Chunked => {
            pm_http::decode_chunked(body).ok_or_else(|| bad("the chunked body is invalid"))?
        }
        pm_http::BodyKind::UntilClose => body.to_vec(),
    };
    Ok((head.status, body))
}

/// The claims the callback checks, for an ID token that has just been received.
pub(crate) fn expectations<'a>(p: &'a OidcProvider, nonce: &'a str, now: i64) -> Expect<'a> {
    Expect {
        issuer: &p.issuer,
        client_id: &p.client_id,
        nonce,
        now,
        group_claim: p.group_claim.as_deref(),
        required_acr: &p.required_acr,
        required_amr: &p.required_amr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn addresses_are_checked_at_connect_time() {
        assert!(address_ok(&ips(&["203.0.113.5", "2001:db8::1"]), false).is_ok());
        // On-premises providers live on private addresses.
        assert!(address_ok(&ips(&["10.1.2.3", "192.168.0.9", "fd00::1"]), false).is_ok());
        for bad in
            ["169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "::ffff:169.254.169.254"]
        {
            assert!(address_ok(&ips(&[bad]), false).is_err(), "{bad}");
        }
        // One bad address among good ones is enough.
        assert!(address_ok(&ips(&["203.0.113.5", "169.254.169.254"]), false).is_err());
        // Plain http is for loopback only.
        assert!(address_ok(&ips(&["127.0.0.1", "::1"]), true).is_ok());
        assert!(address_ok(&ips(&["203.0.113.5"]), true).is_err());
        assert!(address_ok(&ips(&["10.0.0.1"]), true).is_err());
    }

    #[test]
    fn responses_are_framed_and_bounded() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(complete(ok, "GET"));
        assert_eq!(parse_response(ok, "GET").unwrap(), (200, b"hello".to_vec()));
        // Not complete until the whole announced body is there.
        assert!(!complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", "GET"));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", "GET").is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(complete(chunked, "GET"));
        assert_eq!(parse_response(chunked, "GET").unwrap().1, b"hello");
        // Until close: only the end of the stream completes it.
        let open = b"HTTP/1.1 200 OK\r\n\r\nabc";
        assert!(!complete(open, "GET"));
        assert_eq!(parse_response(open, "GET").unwrap().1, b"abc");
        // Garbage is an error, not a panic.
        assert!(parse_response(b"nonsense", "GET").is_err());
        assert!(parse_response(b"", "GET").is_err());
        // A redirect is a status for the caller to refuse, with no body followed.
        assert_eq!(
            parse_response(b"HTTP/1.1 302 Found\r\nLocation: http://x/\r\nContent-Length: 0\r\n\r\n", "GET").unwrap().0,
            302
        );
    }

    #[test]
    fn error_codes_are_coarse() {
        assert_eq!(FlowError::Fetch("x".into()).code(), "provider_unreachable");
        assert_eq!(FlowError::Token("x".into()).code(), "provider_error");
        assert_eq!(FlowError::IdToken(JwtError::Claim("nonce mismatch")).code(), "invalid_token");
        assert_eq!(FlowError::IdToken(JwtError::Claim("acr not accepted")).code(), "assurance_not_met");
    }
}
