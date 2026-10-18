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
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use time::{Duration, OffsetDateTime};

pub use tokio_rustls::{TlsAcceptor, TlsConnector};

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
}
