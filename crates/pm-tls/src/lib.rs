//! TLS for the proxy: a local certificate authority that issues per-host
//! certificates for interception, and an upstream connector.
//!
//! The CA key is unique to each install and is written with owner-only
//! permissions. Upstream certificates are not verified by default, because
//! pentest targets often use self-signed or internal certificates.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
pub use rustls::ServerConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use time::{Duration, OffsetDateTime};

pub use tokio_rustls::rustls::server::Acceptor;
pub use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};

const CA_CERT_FILE: &str = "proxymind-ca.pem";
const CA_KEY_FILE: &str = "proxymind-ca.key";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The local certificate authority used to intercept TLS.
pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    cert_path: PathBuf,
    /// One key shared by all leaf certificates. Generating a key per host is
    /// slow and adds no security for a local interception CA.
    leaf_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// Loads the CA from `dir`, or creates a new one there.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        let (ca_pem, key) = if cert_path.exists() && key_path.exists() {
            let pem = std::fs::read_to_string(&cert_path)?;
            let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?;
            (pem, key)
        } else {
            let key = KeyPair::generate()?;
            let cert = ca_params().self_signed(&key)?;
            write_private(&key_path, key.serialize_pem().as_bytes())?;
            std::fs::write(&cert_path, cert.pem())?;
            tracing::info!(path = %cert_path.display(), "created a new ProxyMind CA");
            (cert.pem(), key)
        };

        let ca_der = CertificateDer::from(pem_to_der(&ca_pem)?);
        let issuer = Issuer::from_ca_cert_der(&ca_der, key).context("loading CA certificate")?;
        Ok(Self {
            issuer,
            ca_der,
            ca_pem,
            cert_path,
            leaf_key: KeyPair::generate()?,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM form, for installing in a browser or OS.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// A TLS server config presenting a certificate for `host`. Cached.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.to_ascii_lowercase();
        if let Some(cfg) = self.cache.lock().get(&host) {
            return Ok(cfg.clone());
        }
        let leaf = leaf_params(&host)?.signed_by(&self.leaf_key, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone(), self.ca_der.clone()], key)?;
        // HTTP/2 to the client comes in milestone M1; offer HTTP/1.1 only for now.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.cache.lock().insert(host, cfg.clone());
        Ok(cfg)
    }
}

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "ProxyMind CA");
    dn.push(DnType::OrganizationName, "ProxyMind");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(3650);
    p
}

fn leaf_params(host: &str) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(vec![host.to_string()])?;
    p.distinguished_name.push(DnType::CommonName, host);
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    let now = OffsetDateTime::now_utc();
    // Browsers reject leaf certificates valid for more than 398 days.
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(365);
    Ok(p)
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    Ok(CertificateDer::from_pem_slice(pem.as_bytes()).context("parsing CA PEM")?.to_vec())
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

/// Client config for talking to targets. When `verify` is false, any
/// server certificate is accepted (the usual choice for pentesting).
pub fn upstream_client_config(verify: bool) -> Result<Arc<ClientConfig>> {
    client_config(verify, None)
}

/// Like [`upstream_client_config`], presenting a client certificate (mutual
/// TLS). `cert_pem` holds the certificate chain, leaf first; `key_pem` the
/// private key (PKCS#8, PKCS#1 or SEC1).
pub fn upstream_client_config_with_cert(verify: bool, cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ClientConfig>> {
    use rustls::pki_types::pem::PemObject;
    let chain = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("reading the client certificate PEM")?;
    anyhow::ensure!(!chain.is_empty(), "no certificate found in the client certificate PEM");
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("reading the client private key PEM")?;
    client_config(verify, Some((chain, key)))
}

fn client_config(
    verify: bool,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let builder = if verify {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots)
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider())))
    };
    let mut cfg = match client_auth {
        Some((chain, key)) => {
            builder.with_client_auth_cert(chain, key).context("the client certificate and key don't match")?
        }
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).context("invalid TLS server name")
}

/// What the start of a TLS connection says about the server name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// More bytes are needed to see the whole first record.
    Incomplete,
    /// A complete ClientHello with this server name (None: no SNI).
    Sni(Option<String>),
    /// Not a TLS ClientHello.
    NotHello,
}

/// Reads the server name (SNI) from the first TLS record of a connection
/// without consuming it, so the bytes can still be tunnelled or handed to
/// the TLS acceptor. Pure parsing; never panics on bad input.
pub fn peek_client_hello(buf: &[u8]) -> Hello {
    if buf.len() < 5 {
        return Hello::Incomplete;
    }
    if buf[0] != 0x16 {
        return Hello::NotHello;
    }
    let len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + len {
        return Hello::Incomplete;
    }
    match sni_in_handshake(&buf[5..5 + len]) {
        Some(sni) => Hello::Sni(sni),
        None => Hello::NotHello,
    }
}

/// `Some(None)`: a ClientHello without SNI; `None`: malformed.
fn sni_in_handshake(h: &[u8]) -> Option<Option<String>> {
    struct R<'a>(&'a [u8]);
    impl<'a> R<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            Some(a)
        }
        fn u8(&mut self) -> Option<usize> {
            self.take(1).map(|b| usize::from(b[0]))
        }
        fn u16(&mut self) -> Option<usize> {
            self.take(2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        }
    }
    let mut r = R(h);
    if r.u8()? != 1 {
        return None; // not a ClientHello
    }
    r.take(3)?; // length: the record may hold only part of a large hello
    r.take(2 + 32)?; // version, random
    let n = r.u8()?;
    r.take(n)?; // session id
    let n = r.u16()?;
    r.take(n)?; // cipher suites
    let n = r.u8()?;
    r.take(n)?; // compression
    if r.0.is_empty() {
        return Some(None);
    }
    let n = r.u16()?;
    let mut ext = R(r.take(n).unwrap_or(r.0));
    while let (Some(kind), Some(len)) = (ext.u16(), ext.u16()) {
        let data = ext.take(len)?;
        if kind == 0 {
            let mut d = R(data);
            d.u16()?;
            if d.u8()? != 0 {
                return Some(None);
            }
            let n = d.u16()?;
            let name = std::str::from_utf8(d.take(n)?).ok()?;
            return Some(Some(name.to_ascii_lowercase()));
        }
    }
    Some(None)
}

/// Accepts any upstream certificate but still checks handshake signatures,
/// so the TLS session itself is sound.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_reloads_same_ca() {
        let dir = std::env::temp_dir().join(format!("pm-tls-test-{}", std::process::id()));
        let a = CertAuthority::load_or_create(&dir).unwrap();
        let b = CertAuthority::load_or_create(&dir).unwrap();
        assert_eq!(a.ca_pem(), b.ca_pem());
        b.server_config("example.com").unwrap();
        b.server_config("127.0.0.1").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CA_KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reads_sni_from_a_real_client_hello() {
        let cfg = upstream_client_config(false).unwrap();
        let mut conn = rustls::ClientConnection::new(cfg, server_name("Pinned.Example.com").unwrap()).unwrap();
        let mut hello = Vec::new();
        conn.write_tls(&mut hello).unwrap();
        assert_eq!(peek_client_hello(&hello), Hello::Sni(Some("pinned.example.com".into())));
        assert_eq!(peek_client_hello(&hello[..hello.len() - 1]), Hello::Incomplete);
        assert_eq!(peek_client_hello(b"GET / HTTP/1.1\r\n"), Hello::NotHello);
        // Truncated or garbled records never panic.
        for cut in 5..hello.len() {
            let mut b = hello[..cut].to_vec();
            b[3..5].copy_from_slice(&((cut - 5) as u16).to_be_bytes());
            let _ = peek_client_hello(&b);
        }
    }
}
