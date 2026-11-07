//! Signed plugins and install-time integrity.
//!
//! A plugin folder can carry `proxymind-plugin.sig`: an Ed25519 signature
//! over a digest of every file in the folder. People keep a list of signer
//! keys they trust (`<home>/trusted-keys.json`). On install ProxyMind
//! records each file's SHA-256; before every run it checks those files are
//! unchanged, so a plugin edited after install (by the plugin itself or
//! anything else) stops running until it is installed again. Files created
//! later (caches) aren't checked.

use std::path::{Path, PathBuf};

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{PluginError, Result};

pub const SIGNATURE: &str = "proxymind-plugin.sig";
pub const TRUSTED_KEYS: &str = "trusted-keys.json";
const MAX_FILES: usize = 5000;
const MAX_BYTES: u64 = 100 * 1024 * 1024;
/// Folders and files left out of the digest (VCS data and interpreter caches).
const SKIP_DIRS: &[&str] = &[".git", "__pycache__", ".mypy_cache", ".pytest_cache"];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn sha256(b: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, b).as_ref())
}

/// Every file in `dir` (relative path, SHA-256), sorted, the signature file left out.
pub fn file_hashes(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let ty = entry.file_type()?;
            if ty.is_symlink() {
                return Err(PluginError::Invalid(format!(
                    "{} is a symbolic link: plugins can't contain links",
                    path.display()
                )));
            }
            if ty.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            if name.ends_with(".pyc") || (d == dir && name == SIGNATURE) {
                continue;
            }
            total += entry.metadata()?.len();
            if out.len() >= MAX_FILES || total > MAX_BYTES {
                return Err(PluginError::Invalid("the plugin folder is too big (5000 files or 100 MB at most)".into()));
            }
            let rel = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            out.push((rel, sha256(&std::fs::read(&path)?)));
        }
    }
    out.sort();
    Ok(out)
}

/// The bytes a signature covers: one `sha256  path` line per file.
pub fn digest(files: &[(String, String)]) -> Vec<u8> {
    files.iter().map(|(p, h)| format!("{h}  {p}\n")).collect::<String>().into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureFile {
    /// Who signed (a label; the key is what counts).
    pub signer: String,
    /// Ed25519 public key, hex.
    pub key: String,
    /// Signature over [`digest`], hex.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKey {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Signature {
    #[default]
    Unsigned,
    /// A valid signature; `trusted` when its key is on the user's list.
    Signed { signer: String, key: String, trusted: bool },
}

pub fn load_trusted(home: &Path) -> Result<Vec<TrustedKey>> {
    match std::fs::read_to_string(home.join(TRUSTED_KEYS)) {
        Ok(t) => serde_json::from_str(&t).map_err(|e| PluginError::Invalid(format!("{TRUSTED_KEYS}: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

pub fn save_trusted(home: &Path, keys: &[TrustedKey]) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let text = serde_json::to_string_pretty(keys).map_err(|e| PluginError::Invalid(e.to_string()))?;
    std::fs::write(home.join(TRUSTED_KEYS), text)?;
    Ok(())
}

/// Checks `dir`'s signature against its files. A signature that doesn't
/// match is an error; no signature is `Unsigned`.
pub fn verify(dir: &Path, files: &[(String, String)], trusted: &[TrustedKey]) -> Result<Signature> {
    let text = match std::fs::read_to_string(dir.join(SIGNATURE)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Signature::Unsigned),
        Err(e) => return Err(e.into()),
    };
    let sig: SignatureFile =
        serde_json::from_str(&text).map_err(|e| PluginError::Invalid(format!("{SIGNATURE}: {e}")))?;
    let (Some(key), Some(s)) = (unhex(&sig.key), unhex(&sig.signature)) else {
        return Err(PluginError::Invalid(format!("{SIGNATURE}: key and signature must be hex")));
    };
    UnparsedPublicKey::new(&ED25519, &key).verify(&digest(files), &s).map_err(|_| {
        PluginError::Invalid("the signature doesn't match the plugin's files: refusing to install".into())
    })?;
    let key_hex = hex(&key);
    let trusted = trusted.iter().any(|t| t.key.eq_ignore_ascii_case(&key_hex));
    Ok(Signature::Signed { signer: sig.signer.chars().take(80).collect(), key: key_hex, trusted })
}

/// A new signing key: (PKCS#8 private key bytes, public key hex).
pub fn keygen() -> Result<(Vec<u8>, String)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| PluginError::Invalid("no randomness".into()))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| PluginError::Invalid("bad key".into()))?;
    Ok((pkcs8.as_ref().to_vec(), hex(pair.public_key().as_ref())))
}

/// Signs `dir` with a PKCS#8 key and writes its signature file.
pub fn sign(dir: &Path, pkcs8: &[u8], signer: &str) -> Result<SignatureFile> {
    let pair =
        Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| PluginError::Invalid("not an Ed25519 PKCS#8 key".into()))?;
    let files = file_hashes(dir)?;
    let sig = SignatureFile {
        signer: signer.to_string(),
        key: hex(pair.public_key().as_ref()),
        signature: hex(pair.sign(&digest(&files)).as_ref()),
    };
    let text = serde_json::to_string_pretty(&sig).map_err(|e| PluginError::Invalid(e.to_string()))?;
    std::fs::write(dir.join(SIGNATURE), text)?;
    Ok(sig)
}

/// The first recorded file that changed or disappeared since install.
pub fn changed(dir: &Path, recorded: &[(String, String)]) -> Option<String> {
    recorded.iter().find_map(|(rel, h)| match std::fs::read(dir.join(rel)) {
        Ok(b) if &sha256(&b) == h => None,
        _ => Some(rel.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_tamper() {
        let dir = std::env::temp_dir().join(format!("pm-sign-{}-{}", std::process::id(), pm_core::now_ms()));
        std::fs::create_dir_all(dir.join("lib")).unwrap();
        std::fs::write(dir.join("check.py"), "print('hi')").unwrap();
        std::fs::write(dir.join("lib/util.py"), "X = 1").unwrap();
        std::fs::create_dir_all(dir.join("__pycache__")).unwrap();
        std::fs::write(dir.join("__pycache__/util.cpython.pyc"), "cache").unwrap();

        let files = file_hashes(&dir).unwrap();
        assert_eq!(files.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["check.py", "lib/util.py"]);
        assert_eq!(verify(&dir, &files, &[]).unwrap(), Signature::Unsigned);

        let (key, public) = keygen().unwrap();
        sign(&dir, &key, "Alice").unwrap();
        let trusted = vec![TrustedKey { name: "alice".into(), key: public.clone() }];
        let files = file_hashes(&dir).unwrap();
        assert_eq!(
            verify(&dir, &files, &[]).unwrap(),
            Signature::Signed { signer: "Alice".into(), key: public.clone(), trusted: false }
        );
        assert!(matches!(verify(&dir, &files, &trusted).unwrap(), Signature::Signed { trusted: true, .. }));

        // A file changed after signing: the signature no longer matches.
        std::fs::write(dir.join("lib/util.py"), "X = 2").unwrap();
        assert!(verify(&dir, &file_hashes(&dir).unwrap(), &trusted).is_err());
        assert_eq!(changed(&dir, &files).as_deref(), Some("lib/util.py"));
        std::fs::write(dir.join("lib/util.py"), "X = 1").unwrap();
        assert_eq!(changed(&dir, &files), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
