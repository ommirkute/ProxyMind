//! A fake OpenID Connect provider, in process, on 127.0.0.1: discovery, a key set, an authorize endpoint that redirects
//! back, and a token endpoint. It checks what a real provider checks (the `redirect_uri` exactly, PKCE S256, client
//! authentication, a code used once) and can be told to misbehave (`Tweak`, `IssParam`, rotated keys) so each refusal in
//! `pm-api` has a test. Tokens are signed with ring: RS256 with the test RSA key of `pm_accounts::webauthn::soft`, ES256
//! with generated P-256 keys.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use pm_accounts::webauthn::b64url_encode;
use pm_accounts::{Clock, ManualClock};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub enum SigKey {
    Rsa { kid: String, pair: RsaKeyPair },
    Ec { kid: String, pair: EcdsaKeyPair },
}

impl SigKey {
    pub fn rsa(kid: &str) -> Self {
        let der = pm_accounts::webauthn::soft::rsa_test_key_der();
        SigKey::Rsa { kid: kid.into(), pair: RsaKeyPair::from_der(&der).expect("the test RSA key") }
    }

    pub fn ec(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        SigKey::Ec {
            kid: kid.into(),
            pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap(),
        }
    }

    pub fn kid(&self) -> &str {
        match self {
            SigKey::Rsa { kid, .. } | SigKey::Ec { kid, .. } => kid,
        }
    }

    pub fn alg(&self) -> &'static str {
        match self {
            SigKey::Rsa { .. } => "RS256",
            SigKey::Ec { .. } => "ES256",
        }
    }

    fn jwk(&self) -> Value {
        match self {
            SigKey::Rsa { kid, pair } => {
                // RSAPublicKey DER: SEQUENCE { INTEGER n, INTEGER e }.
                let der = pair.public().as_ref();
                let (n, e) = parse_rsa_public(der);
                json!({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": b64url_encode(&n), "e": b64url_encode(&e)})
            }
            SigKey::Ec { kid, pair } => {
                let p = pair.public_key().as_ref();
                json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
                       "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..])})
            }
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            SigKey::Rsa { pair, .. } => {
                let mut sig = vec![0u8; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut sig).unwrap();
                sig
            }
            SigKey::Ec { pair, .. } => pair.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec(),
        }
    }
}

/// `(n, e)` big-endian, without leading zeros, from an `RSAPublicKey` DER.
fn parse_rsa_public(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn len(d: &[u8], i: &mut usize) -> usize {
        let b = d[*i];
        *i += 1;
        if b < 0x80 {
            return usize::from(b);
        }
        let n = usize::from(b & 0x7f);
        let mut v = 0usize;
        for _ in 0..n {
            v = (v << 8) | usize::from(d[*i]);
            *i += 1;
        }
        v
    }
    let mut i = 1;
    let _ = len(der, &mut i);
    let mut ints = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[i], 0x02);
        i += 1;
        let l = len(der, &mut i);
        let v = &der[i..i + l];
        i += l;
        let start = v.iter().position(|b| *b != 0).unwrap_or(0);
        ints.push(v[start..].to_vec());
    }
    (ints.remove(0), ints.remove(0))
}

/// Who the provider says is signing in.
#[derive(Clone)]
pub struct Grant {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub groups: Vec<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

impl Grant {
    pub fn new(sub: &str) -> Self {
        Self {
            sub: sub.into(),
            email: None,
            email_verified: false,
            name: Some("Test Person".into()),
            preferred_username: None,
            groups: vec![],
            acr: None,
            amr: vec![],
        }
    }

    pub fn email(mut self, e: &str, verified: bool) -> Self {
        self.email = Some(e.into());
        self.email_verified = verified;
        self
    }

    pub fn groups(mut self, g: &[&str]) -> Self {
        self.groups = g.iter().map(|s| s.to_string()).collect();
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NonceMode {
    Real,
    Wrong,
    Missing,
}

/// What to get wrong in the ID token. The default is a good token.
#[derive(Clone)]
pub struct Tweak {
    pub iss: Option<String>,
    pub aud: Option<Value>,
    pub azp: Option<Value>,
    pub nonce: NonceMode,
    pub exp_delta: i64,
    pub iat_delta: i64,
    /// `none` or `HS256` (signed with the client secret).
    pub alg: Option<&'static str>,
    pub jku: Option<String>,
    /// Sign with this key (an index into `IdpInner::keys`).
    pub signer: usize,
    /// Put this `kid` in the header.
    pub kid: Option<String>,
}

impl Default for Tweak {
    fn default() -> Self {
        Self {
            iss: None,
            aud: None,
            azp: None,
            nonce: NonceMode::Real,
            exp_delta: 300,
            iat_delta: 0,
            alg: None,
            jku: None,
            signer: 0,
            kid: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum IssParam {
    Correct,
    Missing,
    Wrong(String),
}

struct CodeRec {
    challenge: String,
    nonce: String,
    used: bool,
    grant: Grant,
}

pub struct IdpInner {
    /// Every key the provider has; `published` says which ones the key set lists.
    pub keys: Vec<SigKey>,
    pub published: Vec<usize>,
    pub grant: Grant,
    pub tweak: Tweak,
    pub iss_param: IssParam,
    /// Discovery says `authorization_response_iss_parameter_supported`.
    pub advertise_iss_param: bool,
    pub discovery_issuer: Option<String>,
    pub discovery_http_endpoint: bool,
    pub token_status: Option<u16>,
    codes: HashMap<String, CodeRec>,
    pub hits: HashMap<String, usize>,
    pub pkce_failures: usize,
    pub bad_redirect_uris: usize,
    pub last_code: Option<String>,
    pub last_verifier: Option<String>,
    pub last_id_token: Option<String>,
    pub authorize_queries: Vec<HashMap<String, String>>,
}

pub struct Shared {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub clock: Arc<ManualClock>,
    pub inner: Mutex<IdpInner>,
}

pub struct Idp {
    pub port: u16,
    pub shared: Arc<Shared>,
}

impl std::ops::Deref for Idp {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.shared
    }
}

fn form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
}

impl Idp {
    /// A provider that returns the browser to `redirect_uri` and knows `client_id` / `client_secret`.
    pub async fn start(clock: Arc<ManualClock>, redirect_uri: &str, client_secret: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let inner = IdpInner {
            keys: vec![SigKey::rsa("rsa-1"), SigKey::ec("es-1"), SigKey::ec("es-2")],
            published: vec![0, 1],
            grant: Grant::new("sub-default"),
            tweak: Tweak::default(),
            iss_param: IssParam::Correct,
            advertise_iss_param: true,
            discovery_issuer: None,
            discovery_http_endpoint: false,
            token_status: None,
            codes: HashMap::new(),
            hits: HashMap::new(),
            pkce_failures: 0,
            bad_redirect_uris: 0,
            last_code: None,
            last_verifier: None,
            last_id_token: None,
            authorize_queries: vec![],
        };
        let shared = Arc::new(Shared {
            issuer: format!("http://127.0.0.1:{port}"),
            client_id: "proxymind-test".into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            clock,
            inner: Mutex::new(inner),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/evil", get(evil))
            .with_state(shared.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Idp { port, shared }
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut IdpInner) -> T) -> T {
        f(&mut self.shared.inner.lock().unwrap())
    }

    pub fn hits(&self, what: &str) -> usize {
        self.with(|i| i.hits.get(what).copied().unwrap_or(0))
    }

    pub fn set_grant(&self, g: Grant) {
        self.with(|i| i.grant = g);
    }

    pub fn set_tweak(&self, t: Tweak) {
        self.with(|i| i.tweak = t);
    }

    pub fn reset(&self) {
        self.with(|i| {
            i.tweak = Tweak::default();
            i.iss_param = IssParam::Correct;
            i.advertise_iss_param = true;
            i.discovery_issuer = None;
            i.token_status = None;
        });
    }
}

fn bump(i: &mut IdpInner, what: &str) {
    *i.hits.entry(what.to_string()).or_default() += 1;
}

async fn discovery(State(s): State<Arc<Shared>>) -> Response {
    let mut i = s.inner.lock().unwrap();
    bump(&mut i, "discovery");
    let issuer = i.discovery_issuer.clone().unwrap_or_else(|| s.issuer.clone());
    let token = if i.discovery_http_endpoint {
        "http://idp.example.invalid/token".to_string()
    } else {
        format!("{}/token", s.issuer)
    };
    let doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", s.issuer),
        "token_endpoint": token,
        "jwks_uri": format!("{}/jwks", s.issuer),
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "authorization_response_iss_parameter_supported": i.advertise_iss_param,
    });
    axum::Json(doc).into_response()
}

async fn jwks(State(s): State<Arc<Shared>>) -> Response {
    let mut i = s.inner.lock().unwrap();
    bump(&mut i, "jwks");
    let keys: Vec<Value> = i.published.iter().map(|k| i.keys[*k].jwk()).collect();
    axum::Json(json!({"keys": keys})).into_response()
}

async fn evil(State(s): State<Arc<Shared>>) -> Response {
    bump(&mut s.inner.lock().unwrap(), "evil");
    axum::Json(json!({"keys": []})).into_response()
}

fn bad(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

async fn authorize(State(s): State<Arc<Shared>>, uri: Uri) -> Response {
    let q = form(uri.query().unwrap_or(""));
    let mut i = s.inner.lock().unwrap();
    bump(&mut i, "authorize");
    i.authorize_queries.push(q.clone());
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    if get("redirect_uri") != s.redirect_uri {
        i.bad_redirect_uris += 1;
        return bad("redirect_uri is not registered");
    }
    if get("response_type") != "code" || get("client_id") != s.client_id || get("code_challenge_method") != "S256" {
        return bad("bad request");
    }
    if get("state").is_empty()
        || get("nonce").is_empty()
        || get("code_challenge").is_empty()
        || !get("scope").split(' ').any(|x| x == "openid")
    {
        return bad("missing parameter");
    }
    let code = b64url_encode(&ring_random());
    let grant = i.grant.clone();
    i.codes.insert(code.clone(), CodeRec { challenge: get("code_challenge"), nonce: get("nonce"), used: false, grant });
    i.last_code = Some(code.clone());
    let mut loc = format!(
        "{}?code={code}&state={}",
        s.redirect_uri,
        url::form_urlencoded::byte_serialize(get("state").as_bytes()).collect::<String>()
    );
    match &i.iss_param {
        IssParam::Correct => loc.push_str(&format!(
            "&iss={}",
            url::form_urlencoded::byte_serialize(s.issuer.as_bytes()).collect::<String>()
        )),
        IssParam::Wrong(w) => {
            loc.push_str(&format!("&iss={}", url::form_urlencoded::byte_serialize(w.as_bytes()).collect::<String>()))
        }
        IssParam::Missing => {}
    }
    let mut h = HeaderMap::new();
    h.insert(header::LOCATION, loc.parse().unwrap());
    (StatusCode::FOUND, h).into_response()
}

fn ring_random() -> [u8; 24] {
    let mut b = [0u8; 24];
    ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut b).unwrap();
    b
}

fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b = v.strip_prefix("Basic ")?;
    let raw = String::from_utf8(b64_std_decode(b)?).ok()?;
    let (id, secret) = raw.split_once(':')?;
    let dec = |t: &str| {
        url::form_urlencoded::parse(format!("x={t}").as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default()
    };
    Some((dec(id), dec(secret)))
}

fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    const A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').chars() {
        buf = (buf << 6) | u32::try_from(A.find(c)?).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

async fn token(State(s): State<Arc<Shared>>, headers: HeaderMap, body: String) -> Response {
    let f = form(&body);
    let mut i = s.inner.lock().unwrap();
    bump(&mut i, "token");
    if let Some(status) = i.token_status {
        return (StatusCode::from_u16(status).unwrap(), axum::Json(json!({"error": "server_error"}))).into_response();
    }
    let json_err = |e: &str| (StatusCode::BAD_REQUEST, axum::Json(json!({"error": e}))).into_response();
    // Client authentication: Basic with the id and the secret.
    match basic(&headers) {
        Some((id, secret)) if id == s.client_id && secret == s.client_secret => {}
        _ => return (StatusCode::UNAUTHORIZED, axum::Json(json!({"error": "invalid_client"}))).into_response(),
    }
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return json_err("unsupported_grant_type");
    }
    if f.get("redirect_uri") != Some(&s.redirect_uri) {
        i.bad_redirect_uris += 1;
        return json_err("invalid_grant");
    }
    let code = f.get("code").cloned().unwrap_or_default();
    let verifier = f.get("code_verifier").cloned().unwrap_or_default();
    i.last_verifier = Some(verifier.clone());
    let challenge = b64url_encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    let Some(rec) = i.codes.get_mut(&code) else { return json_err("invalid_grant") };
    if rec.used {
        return json_err("invalid_grant");
    }
    rec.used = true;
    if rec.challenge != challenge {
        i.pkce_failures += 1;
        return json_err("invalid_grant");
    }
    let (nonce, grant) = (rec.nonce.clone(), rec.grant.clone());
    let id_token = make_token(&s, &i, &nonce, &grant);
    i.last_id_token = Some(id_token.clone());
    axum::Json(json!({"access_token": "at-not-used", "token_type": "Bearer", "id_token": id_token})).into_response()
}

fn make_token(s: &Shared, i: &IdpInner, nonce: &str, g: &Grant) -> String {
    let now = s.clock.now();
    let t = &i.tweak;
    let mut claims = json!({
        "iss": t.iss.clone().unwrap_or_else(|| s.issuer.clone()),
        "sub": g.sub,
        "aud": t.aud.clone().unwrap_or_else(|| json!(s.client_id)),
        "exp": now + t.exp_delta,
        "iat": now + t.iat_delta,
        "groups": g.groups,
        "email_verified": g.email_verified,
    });
    let obj = claims.as_object_mut().unwrap();
    match t.nonce {
        NonceMode::Real => drop(obj.insert("nonce".into(), json!(nonce))),
        NonceMode::Wrong => drop(obj.insert("nonce".into(), json!("not-the-nonce"))),
        NonceMode::Missing => {}
    }
    if let Some(a) = &t.azp {
        obj.insert("azp".into(), a.clone());
    }
    for (k, v) in
        [("email", &g.email), ("name", &g.name), ("preferred_username", &g.preferred_username), ("acr", &g.acr)]
    {
        if let Some(v) = v {
            obj.insert(k.into(), json!(v));
        }
    }
    if !g.amr.is_empty() {
        obj.insert("amr".into(), json!(g.amr));
    }
    let key = &i.keys[t.signer];
    let mut header = json!({"typ": "JWT", "alg": t.alg.unwrap_or_else(|| key.alg())});
    header["kid"] = json!(t.kid.clone().unwrap_or_else(|| key.kid().to_string()));
    if let Some(j) = &t.jku {
        header["jku"] = json!(j);
    }
    let input =
        format!("{}.{}", b64url_encode(header.to_string().as_bytes()), b64url_encode(claims.to_string().as_bytes()));
    let sig = match t.alg {
        Some("none") => Vec::new(),
        Some("HS256") => ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, s.client_secret.as_bytes()),
            input.as_bytes(),
        )
        .as_ref()
        .to_vec(),
        _ => key.sign(input.as_bytes()),
    };
    format!("{input}.{}", b64url_encode(&sig))
}

// ---- a tiny client for the browser's part ----------------------------------------------------------------------

/// GETs `location` (an absolute `http://127.0.0.1:<port>/…` URL, as the server redirected the browser to it) and returns
/// the status and the `Location` header of the answer.
pub async fn browser_get(location: &str) -> (u16, Option<String>) {
    let url = url::Url::parse(location).expect("an absolute URL");
    let port = url.port().expect("a port");
    let mut path = url.path().to_string();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text.split(' ').nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    let loc = text
        .lines()
        .find_map(|l| l.strip_prefix("location: ").or_else(|| l.strip_prefix("Location: ")))
        .map(|l| l.trim().to_string());
    (status, loc)
}
