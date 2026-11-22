//! TLS for the project server (ADR-0022, "Transport for the project server").
//!
//! Three ways to get a server certificate, and one client-side check:
//!
//! * **Your own certificate** ([`ServerTls::from_files`]): PEM chain and key, re-read when the files change
//!   ([`ReloadingCert`]), so certbot, Caddy or a corporate CA need no code here. A bad replacement keeps the old
//!   certificate and logs a warning.
//! * **Self-signed with a pin** ([`SelfSigned`]): a P-256 key and a one-year certificate made with `rcgen`, kept in the
//!   server home and reused on restart (same key, same pin). The pin is the SHA-256 of the certificate's
//!   SubjectPublicKeyInfo, written `sha256:<base64>` ([`Pin`]).
//! * **Pinned clients** ([`PinVerifier`], [`pin_client_config`]): a `rustls` certificate verifier that accepts exactly
//!   one public key and **fails hard** on any other. It ignores host names and validity dates on purpose (the key is
//!   the identity; renewing a certificate with the same key keeps the pin).
//!
//! **The interception CA has nothing to do with this module.** [`CertAuthority`](crate::CertAuthority) is never
//! consulted here, and the certificates made here are self-signed, never issued by it (a test checks the issuer).
//! Devices that trust the interception CA gain nothing from the server, and a server compromise yields no CA key.
//!
//! Protocol settings: TLS 1.3 preferred and 1.2 allowed (the `rustls` defaults on `ring`), ALPN `h2` then
//! `http/1.1`; `rustls` has no TLS compression.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PublicKeyData,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use time::{Duration as TimeDuration, OffsetDateTime};

pub use tokio_rustls::client::TlsStream as ClientTlsStream;
pub use tokio_rustls::server::TlsStream as ServerTlsStream;

use super::{provider, write_private};

/// How often at most the certificate files are looked at (on a handshake).
pub const RELOAD_CHECK: Duration = Duration::from_secs(3);

/// A self-signed certificate is made again (same key) when fewer than this many days are left.
const RENEW_BEFORE_DAYS: i64 = 30;

// ---- pins ------------------------------------------------------------------------------------------------------

/// SHA-256 of a certificate's SubjectPublicKeyInfo (DER input).
pub fn spki_sha256_der(der: &[u8]) -> Result<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("bad certificate: {e}"))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, cert.tbs_certificate.subject_pki.raw);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

/// The identity of a server key: SHA-256 of the SubjectPublicKeyInfo of its certificate.
///
/// Text form: `sha256:` and the 32 bytes as **standard base64 with padding** (44 characters), the form curl's
/// `--pinnedpubkey sha256//…` and Chromium's SPKI lists use. [`Pin::parse`] also accepts 64 hex digits (and `:`
/// separated hex as certificate viewers show it), so a pin copied from either place works.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; 32]);

impl Pin {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn of_cert_der(der: &[u8]) -> Result<Self> {
        Ok(Self(spki_sha256_der(der)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex of the 32 bytes.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `sha256:<base64>` or `sha256:<hex>`; the prefix is required, its case is not.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (algo, value) = text.split_once(':').context("a pin looks like sha256:<base64 or hex>")?;
        anyhow::ensure!(algo.eq_ignore_ascii_case("sha256"), "only sha256 pins are supported");
        let hexish: String = value.chars().filter(|c| *c != ':').collect();
        if hexish.len() == 64 && hexish.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut out = [0u8; 32];
            for (i, chunk) in hexish.as_bytes().chunks(2).enumerate() {
                out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
            }
            return Ok(Self(out));
        }
        let bytes = b64_decode(value.trim()).context("the pin is neither 64 hex digits nor 44 base64 characters")?;
        let out: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("a sha256 pin is 32 bytes"))?;
        Ok(Self(out))
    }

    fn matches(&self, other: &[u8]) -> bool {
        // The pin is public, but compare without stopping at the first difference anyway.
        self.0.len() == other.len()
            && std::hint::black_box(self.0.iter().zip(other).fold(0u8, |acc, (a, b)| acc | (a ^ b))) == 0
    }
}

impl fmt::Display for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", b64_encode(&self.0))
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin({self})")
    }
}

impl FromStr for Pin {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = B64.iter().position(|b| *b == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ---- the client side: accept exactly one key -------------------------------------------------------------------

/// A certificate verifier that accepts a server whose public key hashes to the pin, and nothing else. A mismatch is an
/// error that names both pins, so the person can compare them; there is no fallback and no "trust anyway".
pub struct PinVerifier {
    pin: Pin,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinVerifier").field("pin", &self.pin).finish()
    }
}

impl PinVerifier {
    pub fn new(pin: Pin) -> Self {
        Self { pin, provider: provider() }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = spki_sha256_der(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("the server certificate cannot be read: {e}")))?;
        if self.pin.matches(&got) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "the server's key does not match the pin: expected {}, the server presented {}",
                self.pin,
                Pin(got)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config that talks only to the server holding `pin`'s key (for `proxymind login` and the MCP bridge).
/// `alpn` are the protocols to offer, e.g. `[b"http/1.1"]`.
pub fn pin_client_config(pin: Pin, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>> {
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier::new(pin)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

// ---- the server side: certificate files that may change --------------------------------------------------------

fn load_certified(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>> {
    let cert_pem = std::fs::read(cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("reading the certificate chain in {}", cert_path.display()))?;
    anyhow::ensure!(!chain.is_empty(), "no certificate found in {}", cert_path.display());
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .with_context(|| format!("reading the private key in {}", key_path.display()))?;
    let ck = CertifiedKey::from_der(chain, key, &provider())
        .map_err(|e| anyhow::anyhow!("the certificate and key do not work together: {e}"))?;
    Ok(Arc::new(ck))
}

/// What identifies a version of the two files.
#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    cert: Option<(SystemTime, u64)>,
    key: Option<(SystemTime, u64)>,
}

fn stamp(cert: &Path, key: &Path) -> Stamp {
    let one = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
    Stamp { cert: one(cert), key: one(key) }
}

struct Checked {
    at: Instant,
    seen: Stamp,
}

/// Presents the certificate in two PEM files and picks up a new one when the files change (modification time or
/// length), looking at most every `interval` and only when a client connects. A replacement that does not parse, or
/// whose key does not match, is logged once and the previous certificate stays in use.
pub struct ReloadingCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    interval: Duration,
    current: RwLock<Arc<CertifiedKey>>,
    checked: Mutex<Checked>,
    generation: AtomicU64,
}

impl fmt::Debug for ReloadingCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingCert").field("cert", &self.cert_path).field("key", &self.key_path).finish()
    }
}

impl ReloadingCert {
    /// Loads the files now (an error if they are unusable: a server does not start without a certificate).
    pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self> {
        Self::with_interval(cert_path, key_path, RELOAD_CHECK)
    }

    pub fn with_interval(cert_path: &Path, key_path: &Path, interval: Duration) -> Result<Self> {
        let seen = stamp(cert_path, key_path);
        let current = load_certified(cert_path, key_path)?;
        Ok(Self {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            interval,
            current: RwLock::new(current),
            checked: Mutex::new(Checked { at: Instant::now(), seen }),
            generation: AtomicU64::new(0),
        })
    }

    /// How many times a new certificate has been loaded since start.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The pin of the certificate in use now.
    pub fn pin(&self) -> Result<Pin> {
        let ck = self.current.read().clone();
        Pin::of_cert_der(ck.end_entity_cert().map_err(|e| anyhow::anyhow!("{e}"))?.as_ref())
    }

    /// Looks at the files if the interval has passed; reloads when they changed. Called on every handshake.
    pub fn check(&self) {
        self.check_at(Instant::now());
    }

    fn check_at(&self, now: Instant) {
        // A handshake that finds another one checking just uses the current certificate.
        let Some(mut checked) = self.checked.try_lock() else { return };
        if now.saturating_duration_since(checked.at) < self.interval {
            return;
        }
        checked.at = now;
        let now_stamp = stamp(&self.cert_path, &self.key_path);
        if now_stamp == checked.seen {
            return;
        }
        // Remember this version before trying it: a bad one is reported once, not on every handshake.
        checked.seen = now_stamp;
        match load_certified(&self.cert_path, &self.key_path) {
            Ok(ck) => {
                *self.current.write() = ck;
                self.generation.fetch_add(1, Ordering::SeqCst);
                tracing::info!("TLS certificate reloaded from {}", self.cert_path.display());
            }
            Err(e) => tracing::warn!(
                "the new TLS certificate files were not loaded ({e:#}); the previous certificate stays in use"
            ),
        }
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.check();
        Some(self.current.read().clone())
    }
}

/// A `rustls` server config for the project server: default protocol versions (1.3, 1.2), ALPN `h2` and `http/1.1`,
/// the certificate from `resolver`.
pub fn project_server_config(resolver: Arc<dyn ResolvesServerCert>) -> Result<Arc<ServerConfig>> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

// ---- self-signed with pinning ----------------------------------------------------------------------------------

const SELF_CERT_FILE: &str = "server-tls.crt.pem";
const SELF_KEY_FILE: &str = "server-tls.key.pem";

/// A self-signed certificate for the server, kept in a folder (the server home): `server-tls.key.pem` (mode 0600) and
/// `server-tls.crt.pem`. The key is made once; the certificate is made again (same key, so the same pin) when it is
/// missing, has under 30 days left, or does not cover all the names asked for.
#[derive(Debug, Clone)]
pub struct SelfSigned {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub pin: Pin,
    /// True when this call made a new key (a new pin: clients must confirm it).
    pub new_key: bool,
}

fn san_names(der: &[u8]) -> Option<(Vec<String>, Vec<Vec<u8>>, i64)> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for n in &san.general_names {
                match n {
                    GeneralName::DNSName(d) => dns.push(d.to_ascii_lowercase()),
                    GeneralName::IPAddress(b) => ips.push(b.to_vec()),
                    _ => {}
                }
            }
        }
    }
    Some((dns, ips, cert.validity().not_after.timestamp()))
}

fn ip_bytes(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    }
}

/// Does the certificate (DER) name every one of `names` (host names or IP addresses)?
fn covers(der: &[u8], names: &[String]) -> bool {
    let Some((dns, ips, _)) = san_names(der) else { return false };
    names.iter().all(|n| match n.parse::<std::net::IpAddr>() {
        Ok(ip) => ips.contains(&ip_bytes(ip)),
        Err(_) => dns.contains(&n.to_ascii_lowercase()),
    })
}

fn self_signed_cert(key: &KeyPair, names: &[String]) -> Result<rcgen::Certificate> {
    let mut p = CertificateParams::new(names.to_vec()).context("a name for the certificate is not valid")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, names.first().map_or("ProxyMind server", String::as_str));
    dn.push(DnType::OrganizationName, "ProxyMind server (self-signed)");
    p.distinguished_name = dn;
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - TimeDuration::days(1);
    p.not_after = now + TimeDuration::days(365);
    Ok(p.self_signed(key)?)
}

impl SelfSigned {
    /// Loads or makes the key and certificate in `dir` for `names` (at least one host name or IP address).
    pub fn load_or_create(dir: &Path, names: &[String]) -> Result<Self> {
        anyhow::ensure!(!names.is_empty(), "a self-signed certificate needs at least one host name or address");
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let cert_path = dir.join(SELF_CERT_FILE);
        let key_path = dir.join(SELF_KEY_FILE);
        let (key, new_key) = match std::fs::read_to_string(&key_path) {
            Ok(pem) => (KeyPair::from_pem(&pem).context("reading the self-signed key")?, false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
                write_private(&key_path, key.serialize_pem().as_bytes())?;
                (key, true)
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", key_path.display())),
        };
        let key_hash = ring::digest::digest(&ring::digest::SHA256, &key.subject_public_key_info());
        let reusable =
            std::fs::read(&cert_path).ok().and_then(|pem| CertificateDer::from_pem_slice(&pem).ok()).filter(|der| {
                let same_key = spki_sha256_der(der.as_ref()).is_ok_and(|h| h.as_slice() == key_hash.as_ref());
                let fresh = san_names(der.as_ref()).is_some_and(|(_, _, end)| {
                    end > (OffsetDateTime::now_utc() + TimeDuration::days(RENEW_BEFORE_DAYS)).unix_timestamp()
                });
                same_key && fresh && covers(der.as_ref(), names)
            });
        let der = match reusable {
            Some(der) => der,
            None => {
                let cert = self_signed_cert(&key, names)?;
                // The certificate is public; the key's file is already 0600.
                std::fs::write(&cert_path, cert.pem()).with_context(|| format!("writing {}", cert_path.display()))?;
                cert.der().clone()
            }
        };
        Ok(Self { cert_path, key_path, pin: Pin::of_cert_der(der.as_ref())?, new_key })
    }
}

// ---- what the server presents ---------------------------------------------------------------------------------

/// The server's TLS setup: the config to hand to an acceptor, the pin, and whether the certificate is self-signed.
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    pub certs: Arc<ReloadingCert>,
    /// A self-signed certificate: no HSTS, clients pin the key.
    pub self_signed: bool,
    /// The pin when the certificate was loaded; use [`ReloadingCert::pin`] for the current one.
    pub pin: Pin,
}

impl ServerTls {
    /// The operator's own certificate (PEM chain, leaf first) and key, reloaded when the files change.
    pub fn from_files(cert: &Path, key: &Path) -> Result<Self> {
        let certs = Arc::new(ReloadingCert::new(cert, key)?);
        let pin = certs.pin()?;
        Ok(Self { config: project_server_config(certs.clone())?, certs, self_signed: false, pin })
    }

    /// A self-signed certificate kept in `dir` for `names`.
    pub fn self_signed(dir: &Path, names: &[String]) -> Result<(Self, SelfSigned)> {
        let made = SelfSigned::load_or_create(dir, names)?;
        let certs = Arc::new(ReloadingCert::new(&made.cert_path, &made.key_path)?);
        let tls = Self { config: project_server_config(certs.clone())?, certs, self_signed: true, pin: made.pin };
        Ok((tls, made))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pm-tls-server-{name}-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Runs a TLS handshake between two in-memory endpoints; the server's error wins over the client's.
    fn handshake(client: Arc<ClientConfig>, server: Arc<ServerConfig>) -> Result<Option<Vec<u8>>, rustls::Error> {
        let mut c = rustls::ClientConnection::new(client, ServerName::try_from("pm.test").unwrap()).unwrap();
        let mut s = rustls::ServerConnection::new(server).unwrap();
        for _ in 0..20 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                s.read_tls(&mut buf.as_slice()).unwrap();
                s.process_new_packets()?;
            }
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                c.read_tls(&mut buf.as_slice()).unwrap();
                c.process_new_packets()?;
            }
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok(c.alpn_protocol().map(<[u8]>::to_vec));
            }
        }
        panic!("the handshake did not finish");
    }

    #[test]
    fn pin_text_round_trips_and_accepts_hex() {
        let pin = Pin::from_bytes(std::array::from_fn(|i| (i * 7 + 1) as u8));
        let text = pin.to_string();
        assert!(text.starts_with("sha256:") && text.len() == 7 + 44, "{text}");
        assert_eq!(Pin::parse(&text).unwrap(), pin);
        assert_eq!(Pin::parse(&format!("SHA256:{}", pin.hex())).unwrap(), pin);
        let colons: Vec<String> = pin.as_bytes().iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(Pin::parse(&format!("sha256:{}", colons.join(":"))).unwrap(), pin);
        for bad in ["", "sha256:", "sha1:abcd", "sha256:AAAA", "nothing", "sha256:!!!!"] {
            assert!(Pin::parse(bad).is_err(), "{bad}");
        }
        // base64 vectors
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_decode("Zm9vYg==").unwrap(), b"foob");
    }

    #[test]
    fn self_signed_is_stable_across_restarts_and_keeps_the_pin_on_renewal() {
        let dir = temp("self");
        let names = vec!["pm.test".to_string(), "127.0.0.1".to_string()];
        let a = SelfSigned::load_or_create(&dir, &names).unwrap();
        assert!(a.new_key);
        let cert_a = std::fs::read(&a.cert_path).unwrap();
        let b = SelfSigned::load_or_create(&dir, &names).unwrap();
        assert!(!b.new_key);
        assert_eq!(a.pin, b.pin, "same key, same pin");
        assert_eq!(cert_a, std::fs::read(&b.cert_path).unwrap(), "the certificate is reused, not remade");
        // A new name: a new certificate, the same key.
        let more = vec!["pm.test".to_string(), "127.0.0.1".to_string(), "other.test".to_string()];
        let c = SelfSigned::load_or_create(&dir, &more).unwrap();
        assert_eq!(c.pin, a.pin);
        assert_ne!(cert_a, std::fs::read(&c.cert_path).unwrap());
        // A new key is a new pin, and says so.
        std::fs::remove_file(&a.key_path).unwrap();
        let d = SelfSigned::load_or_create(&dir, &more).unwrap();
        assert!(d.new_key);
        assert_ne!(d.pin, a.pin);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&d.key_path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(SelfSigned::load_or_create(&dir, &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_self_signed_certificate_is_its_own_issuer_and_p256() {
        let dir = temp("issuer");
        let made = SelfSigned::load_or_create(&dir, &["pm.test".to_string(), "::1".to_string()]).unwrap();
        let pem = std::fs::read(&made.cert_path).unwrap();
        let der = CertificateDer::from_pem_slice(&pem).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        // Self-signed: no interception CA signed it, and it is not a CA itself.
        assert_eq!(cert.issuer().to_string(), cert.subject().to_string());
        assert!(!cert.is_ca());
        assert!(cert.public_key().algorithm.algorithm.to_string().contains("1.2.840.10045.2.1"), "EC public key");
        let days = (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()) / 86_400;
        assert!((365..=367).contains(&days), "{days} days");
        assert!(covers(der.as_ref(), &["pm.test".into(), "::1".into()]));
        assert!(!covers(der.as_ref(), &["evil.test".into()]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn right_pin_connects_wrong_pin_fails_hard() {
        let dir = temp("pin");
        let (tls, made) = ServerTls::self_signed(&dir, &["pm.test".to_string()]).unwrap();
        assert!(tls.self_signed);
        let ok = handshake(pin_client_config(made.pin, &[b"h2", b"http/1.1"]).unwrap(), tls.config.clone()).unwrap();
        assert_eq!(ok.as_deref(), Some(b"h2".as_slice()), "ALPN prefers h2");
        let http1 = handshake(pin_client_config(made.pin, &[b"http/1.1"]).unwrap(), tls.config.clone()).unwrap();
        assert_eq!(http1.as_deref(), Some(b"http/1.1".as_slice()));
        let wrong = Pin::from_bytes([9; 32]);
        let err = handshake(pin_client_config(wrong, &[b"http/1.1"]).unwrap(), tls.config.clone()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("does not match the pin") && msg.contains(&made.pin.to_string()), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pin_survives_a_certificate_renewal_with_the_same_key() {
        let dir = temp("renew");
        let (tls, made) = ServerTls::self_signed(&dir, &["pm.test".to_string()]).unwrap();
        let client = pin_client_config(made.pin, &[b"http/1.1"]).unwrap();
        handshake(client.clone(), tls.config).unwrap();
        // A new name makes a new certificate with the same key; a fresh server config still matches the old pin.
        let (tls2, made2) = ServerTls::self_signed(&dir, &["pm.test".to_string(), "second.test".to_string()]).unwrap();
        assert_eq!(made2.pin, made.pin);
        handshake(client, tls2.config).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_pair(dir: &Path, tag: &str, name: &str) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = self_signed_cert(&key, &[name.to_string()]).unwrap();
        let (c, k) = (dir.join(format!("{tag}.crt")), dir.join(format!("{tag}.key")));
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        (c, k)
    }

    fn bump_mtime(path: &Path, secs: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(secs)).unwrap();
    }

    #[test]
    fn changed_files_are_picked_up_and_bad_ones_keep_the_old_certificate() {
        let dir = temp("reload");
        let (cert, key) = write_pair(&dir, "live", "pm.test");
        let r = ReloadingCert::with_interval(&cert, &key, Duration::ZERO).unwrap();
        let first = r.pin().unwrap();
        r.check();
        assert_eq!(r.generation(), 0, "nothing changed");

        // Swap in a new pair (as certbot would).
        let (c2, k2) = write_pair(&dir, "next", "pm.test");
        std::fs::copy(&c2, &cert).unwrap();
        std::fs::copy(&k2, &key).unwrap();
        bump_mtime(&cert, 10);
        bump_mtime(&key, 10);
        r.check();
        assert_eq!(r.generation(), 1);
        let second = r.pin().unwrap();
        assert_ne!(first, second);

        // Garbage: the second certificate stays, the warning is logged, and the same bad files are not retried.
        std::fs::write(&cert, "not a certificate").unwrap();
        bump_mtime(&cert, 20);
        r.check();
        r.check();
        assert_eq!(r.generation(), 1);
        assert_eq!(r.pin().unwrap(), second);

        // A certificate whose key does not match is refused too.
        let (c3, _) = write_pair(&dir, "other", "pm.test");
        std::fs::copy(&c3, &cert).unwrap();
        bump_mtime(&cert, 30);
        r.check();
        assert_eq!(r.generation(), 1);
        assert_eq!(r.pin().unwrap(), second);

        // And a good pair after the bad ones is loaded again.
        let (c4, k4) = write_pair(&dir, "again", "pm.test");
        std::fs::copy(&c4, &cert).unwrap();
        std::fs::copy(&k4, &key).unwrap();
        bump_mtime(&cert, 40);
        bump_mtime(&key, 40);
        r.check();
        assert_eq!(r.generation(), 2);
        assert_ne!(r.pin().unwrap(), second);

        // A handshake sees the reloaded certificate.
        let cfg = project_server_config(Arc::new(r)).unwrap();
        let want =
            Pin::of_cert_der(CertificateDer::from_pem_slice(&std::fs::read(&cert).unwrap()).unwrap().as_ref()).unwrap();
        handshake(pin_client_config(want, &[b"http/1.1"]).unwrap(), cfg).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unusable_files_at_start_are_an_error() {
        let dir = temp("bad");
        let (cert, _) = write_pair(&dir, "a", "pm.test");
        let (_, key) = write_pair(&dir, "b", "pm.test");
        assert!(ReloadingCert::new(&cert, &key).is_err(), "mismatched pair");
        assert!(ReloadingCert::new(&dir.join("missing.crt"), &key).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
