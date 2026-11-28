//! Provider discovery (OpenID Connect Discovery 1.0), PKCE (RFC 7636), the authorization URL and the `iss` response
//! parameter check (RFC 9207). Pure: the caller fetches the document and hands over its bytes.
//!
//! * The document's `issuer` must equal the configured issuer *exactly* (no normalisation: a trailing slash matters),
//!   which is also what stops a provider from vouching for another one.
//! * Every endpoint is `https`, except `http` to a loopback host (tests and a provider on the same machine), and has no
//!   user information or fragment.
//! * PKCE `S256` must not be ruled out by the provider; `plain` is never used.

use ring::digest;
use serde_json::Value;
use url::Url;

use crate::util::random;
use crate::webauthn::b64url_encode;

/// A discovery document or a JWKS longer than this is refused.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// HTTP Basic (`client_secret_basic`), the default of the specification.
    Basic,
    /// The secret in the form body (`client_secret_post`).
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// The provider says it sends the `iss` parameter with the authorization response (RFC 9207): then it is required.
    pub iss_param_supported: bool,
    pub token_auth: TokenAuth,
    /// The signing algorithms the provider lists for ID tokens, if it lists any.
    pub signing_algs: Vec<String>,
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(a) => a.is_loopback(),
        url::Host::Ipv6(a) => a.is_loopback(),
    }
}

/// `https`, or `http` to a loopback host; no credentials in the URL, no fragment. `Err` is a short reason.
pub fn check_endpoint(raw: &str) -> Result<Url, &'static str> {
    if raw.len() > 2048 || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("not a usable URL");
    }
    let url = Url::parse(raw).map_err(|_| "not a URL")?;
    let host = url.host().ok_or("has no host")?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&host) => {}
        "http" => return Err("must use https (plain http is only accepted for localhost)"),
        _ => return Err("must be an https URL"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain a user name or password");
    }
    if url.fragment().is_some() {
        return Err("must not contain a fragment");
    }
    Ok(url)
}

/// What an administrator may enter as the issuer: an endpoint URL without a query. The string is kept exactly as typed.
pub fn check_issuer(raw: &str) -> Result<(), &'static str> {
    let url = check_endpoint(raw)?;
    if url.query().is_some() {
        return Err("must not contain a query");
    }
    Ok(())
}

/// Where the discovery document of `issuer` is (a terminating `/` is removed first, Discovery 1.0 section 4).
pub fn discovery_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.strip_suffix('/').unwrap_or(issuer))
}

fn string_list(v: &Value, key: &str) -> Option<Vec<String>> {
    v.get(key)?.as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
}

/// Reads and checks a discovery document.
pub fn parse_discovery(bytes: &[u8], configured_issuer: &str) -> Result<Discovery, &'static str> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("the discovery document is too large");
    }
    let doc: Value = serde_json::from_slice(bytes).map_err(|_| "the discovery document is not JSON")?;
    let issuer = doc.get("issuer").and_then(Value::as_str).ok_or("the discovery document names no issuer")?;
    if issuer != configured_issuer {
        return Err("the discovery document's issuer is not the configured issuer");
    }
    let endpoint = |key: &'static str| -> Result<String, &'static str> {
        let raw = doc.get(key).and_then(Value::as_str).ok_or("the discovery document lacks an endpoint")?;
        check_endpoint(raw).map_err(|_| "an endpoint in the discovery document is not acceptable (https needed)")?;
        Ok(raw.to_string())
    };
    let (authorization_endpoint, token_endpoint, jwks_uri) =
        (endpoint("authorization_endpoint")?, endpoint("token_endpoint")?, endpoint("jwks_uri")?);
    if let Some(types) = string_list(&doc, "response_types_supported")
        && !types.iter().any(|t| t == "code")
    {
        return Err("the provider does not support the authorization code flow");
    }
    if let Some(methods) = string_list(&doc, "code_challenge_methods_supported")
        && !methods.iter().any(|m| m == "S256")
    {
        return Err("the provider does not support PKCE with S256");
    }
    let signing_algs = string_list(&doc, "id_token_signing_alg_values_supported").unwrap_or_default();
    if !signing_algs.is_empty() && !signing_algs.iter().any(|a| matches!(a.as_str(), "RS256" | "ES256" | "EdDSA")) {
        return Err("the provider signs ID tokens with no algorithm ProxyMind accepts (RS256, ES256, EdDSA)");
    }
    // `client_secret_basic` unless the provider lists methods and not that one but `client_secret_post`.
    let token_auth = match string_list(&doc, "token_endpoint_auth_methods_supported") {
        Some(m) if !m.iter().any(|x| x == "client_secret_basic") && m.iter().any(|x| x == "client_secret_post") => {
            TokenAuth::Post
        }
        _ => TokenAuth::Basic,
    };
    let iss_param_supported =
        doc.get("authorization_response_iss_parameter_supported").and_then(Value::as_bool).unwrap_or(false);
    Ok(Discovery {
        issuer: issuer.to_string(),
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        iss_param_supported,
        token_auth,
        signing_algs,
    })
}

/// RFC 9207: when the authorization response carries `iss` it must be the provider's issuer; when discovery says the
/// provider sends it, it is required. This is what stops a mix-up attack (a response from another provider).
pub fn check_iss_param(param: Option<&str>, issuer: &str, required: bool) -> Result<(), &'static str> {
    match param {
        Some(p) if p == issuer => Ok(()),
        Some(_) => Err("the iss parameter is not this provider's issuer"),
        None if required => Err("the iss parameter is missing"),
        None => Ok(()),
    }
}

/// A PKCE code verifier: 32 random bytes as 43 base64url characters.
pub(crate) fn new_verifier() -> crate::error::Result<String> {
    Ok(b64url_encode(&random::<32>()?))
}

/// `BASE64URL(SHA256(verifier))`, method `S256`.
pub fn pkce_challenge(verifier: &str) -> String {
    b64url_encode(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref())
}

/// What `authorization_url` needs besides the discovery document.
pub struct AuthRequest<'a> {
    pub client_id: &'a str,
    /// `openid` is always added; these are the others.
    pub scopes: &'a [String],
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub code_challenge: &'a str,
}

/// The URL to send the browser to (authorization code flow with PKCE S256).
pub fn authorization_url(d: &Discovery, r: &AuthRequest<'_>) -> Result<String, &'static str> {
    let mut url = Url::parse(&d.authorization_endpoint).map_err(|_| "bad authorization endpoint")?;
    let mut scope = vec!["openid".to_string()];
    scope.extend(r.scopes.iter().filter(|s| s.as_str() != "openid").cloned());
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", r.client_id)
        .append_pair("redirect_uri", r.redirect_uri)
        .append_pair("scope", &scope.join(" "))
        .append_pair("state", r.state)
        .append_pair("nonce", r.nonce)
        .append_pair("code_challenge", r.code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn doc() -> Value {
        json!({"issuer": "https://idp.example/realms/x",
               "authorization_endpoint": "https://idp.example/realms/x/auth",
               "token_endpoint": "https://idp.example/realms/x/token",
               "jwks_uri": "https://idp.example/realms/x/certs",
               "response_types_supported": ["code", "id_token"],
               "code_challenge_methods_supported": ["plain", "S256"],
               "id_token_signing_alg_values_supported": ["RS256"]})
    }

    fn parse(d: &Value) -> Result<Discovery, &'static str> {
        parse_discovery(d.to_string().as_bytes(), "https://idp.example/realms/x")
    }

    #[test]
    fn a_good_document_is_accepted() {
        let d = parse(&doc()).unwrap();
        assert_eq!(d.token_auth, TokenAuth::Basic);
        assert!(!d.iss_param_supported);
        let mut j = doc();
        j["authorization_response_iss_parameter_supported"] = json!(true);
        j["token_endpoint_auth_methods_supported"] = json!(["client_secret_post"]);
        let d = parse(&j).unwrap();
        assert!(d.iss_param_supported);
        assert_eq!(d.token_auth, TokenAuth::Post);
    }

    #[test]
    fn the_issuer_must_match_exactly() {
        for other in ["https://idp.example/realms/x/", "https://IDP.example/realms/x", "https://evil.example/realms/x"]
        {
            let mut j = doc();
            j["issuer"] = json!(other);
            assert!(parse(&j).is_err(), "{other}");
        }
        assert!(parse_discovery(b"{}", "https://idp.example").is_err());
        assert!(parse_discovery(b"nope", "https://idp.example").is_err());
    }

    #[test]
    fn endpoints_need_https_except_loopback() {
        assert!(check_endpoint("https://idp.example/x").is_ok());
        assert!(check_endpoint("http://127.0.0.1:9000/x").is_ok());
        assert!(check_endpoint("http://localhost/x").is_ok());
        assert!(check_endpoint("http://[::1]:9/x").is_ok());
        for bad in [
            "http://idp.example/x",
            "http://127.0.0.1.evil.example/x",
            "ftp://idp.example/",
            "https://user:pw@idp.example/",
            "https://idp.example/#frag",
            "javascript:alert(1)",
            "https://idp.example/ x",
            "",
            "/relative",
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad}");
        }
        for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let mut j = doc();
            j[key] = json!("http://idp.example/plain");
            assert!(parse(&j).is_err(), "{key}");
            let mut j = doc();
            j.as_object_mut().unwrap().remove(key);
            assert!(parse(&j).is_err(), "{key} missing");
        }
        assert!(check_issuer("https://idp.example/realms/x").is_ok());
        assert!(check_issuer("https://idp.example/?a=b").is_err());
    }

    #[test]
    fn capabilities_the_provider_rules_out_are_refused() {
        let mut j = doc();
        j["code_challenge_methods_supported"] = json!(["plain"]);
        assert!(parse(&j).is_err());
        let mut j = doc();
        j["response_types_supported"] = json!(["id_token"]);
        assert!(parse(&j).is_err());
        let mut j = doc();
        j["id_token_signing_alg_values_supported"] = json!(["HS256", "PS256"]);
        assert!(parse(&j).is_err());
    }

    #[test]
    fn the_iss_parameter_rules() {
        assert!(check_iss_param(Some("https://a"), "https://a", true).is_ok());
        assert!(check_iss_param(Some("https://b"), "https://a", false).is_err());
        assert!(check_iss_param(Some("https://a/"), "https://a", false).is_err());
        assert!(check_iss_param(None, "https://a", true).is_err());
        assert!(check_iss_param(None, "https://a", false).is_ok());
    }

    #[test]
    fn discovery_url_drops_one_trailing_slash() {
        assert_eq!(discovery_url("https://a/b"), "https://a/b/.well-known/openid-configuration");
        assert_eq!(discovery_url("https://a/b/"), "https://a/b/.well-known/openid-configuration");
    }

    #[test]
    fn pkce_matches_the_rfc_vector_and_the_url_carries_every_parameter() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(new_verifier().unwrap().len(), 43);
        let d = parse(&doc()).unwrap();
        let url = authorization_url(
            &d,
            &AuthRequest {
                client_id: "pm",
                scopes: &["email".into(), "openid".into(), "groups".into()],
                redirect_uri: "https://pm.example/api/v1/auth/oidc/callback",
                state: "s",
                nonce: "n",
                code_challenge: "c",
            },
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "openid email groups");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["redirect_uri"], "https://pm.example/api/v1/auth/oidc/callback");
        assert_eq!((q["state"].as_str(), q["nonce"].as_str(), q["client_id"].as_str()), ("s", "n", "pm"));
    }
}
