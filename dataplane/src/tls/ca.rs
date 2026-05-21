/// TSMv2 — Local Root CA and per-hostname certificate generation.
///
/// # Purpose
///
/// The TSM data plane operates as a TLS MITM (Man-in-the-Middle) transparent
/// proxy.  When an application connects to api.openai.com:443, the data plane:
///
///   1. Presents the client with a fake certificate for "api.openai.com",
///      signed by the local TSM Root CA.
///   2. Simultaneously opens a real TLS connection to api.openai.com upstream.
///   3. Decrypts, scans, and re-encrypts traffic in both directions.
///
/// For this to work without TLS errors in the client, the TSM Root CA cert
/// must be installed as a trusted CA in the OS / application trust store
/// (see the eprintln! message printed on first run).
///
/// # Key material lifecycle
///
///   - On first startup: generate ECDSA P-256 Root CA key + self-signed cert.
///   - Persist to `~/.tsm/ca.key` (PKCS#8 PEM) and `~/.tsm/ca.crt` (PEM).
///   - Per request: derive a leaf cert for the target hostname, signed by the CA.
///   - Leaf certs are cached in memory for 1 hour (with cap of 512 entries).
///
/// # Implementation
///
/// Uses the `rcgen` crate (0.13) for X.509 certificate generation with
/// ECDSA P-256.  rcgen uses ring internally, so no new crypto primitives are
/// introduced beyond those already in Cargo.toml.
///
/// # rcgen 0.13 signing API
///
///   ```rust
///   // CA cert
///   let ca_key  = KeyPair::generate()?;
///   let ca_cert = params.self_signed(&ca_key)?;
///
///   // Leaf cert signed by CA
///   let leaf_key  = KeyPair::generate()?;
///   let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;
///   ```

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of leaf certs cached in memory simultaneously.
const LEAF_CACHE_CAP: usize = 512;

/// How long a cached leaf cert stays valid before being regenerated.
const LEAF_CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// Subject fields for the Root CA.
const CA_COMMON_NAME: &str = "TSM Local Root CA";
const CA_ORG:         &str = "TSM Sovereign AI Infrastructure";
const CA_COUNTRY:     &str = "US";

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CaError {
    Io(std::io::Error),
    Cert(rcgen::Error),
    HomeDir,
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaError::Io(e)   => write!(f, "CA I/O error: {e}"),
            CaError::Cert(e) => write!(f, "CA cert error: {e}"),
            CaError::HomeDir => write!(f, "cannot determine home directory"),
        }
    }
}

impl From<std::io::Error> for CaError { fn from(e: std::io::Error) -> Self { CaError::Io(e) } }
impl From<rcgen::Error>   for CaError { fn from(e: rcgen::Error)   -> Self { CaError::Cert(e) } }

// ── Leaf cert cache entry ─────────────────────────────────────────────────────

struct CacheEntry {
    /// PEM-encoded leaf certificate.
    cert_pem: Arc<String>,
    /// PEM-encoded private key for this leaf cert.
    key_pem:  Arc<String>,
    /// When this entry was inserted.
    inserted: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted.elapsed() > LEAF_CACHE_TTL
    }
}

// ── LocalCa ──────────────────────────────────────────────────────────────────

/// The TSM local Root CA — generates and signs per-hostname leaf certificates.
///
/// Constructed once at dataplane startup via `LocalCa::load_or_create()`.
/// Wrap in `Arc<LocalCa>` and pass into each connection handler.
pub struct LocalCa {
    /// PEM-encoded CA certificate (for distributing to clients / trust stores).
    pub ca_cert_pem: String,
    /// The rcgen CA certificate object (used as issuer when signing leaves).
    ca_cert: Certificate,
    /// The CA private key (required by rcgen 0.13 `signed_by()` as 3rd arg).
    ca_key: KeyPair,
    /// In-memory cache: hostname → CacheEntry.
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl LocalCa {
    /// Load the CA from disk, or generate and persist a new one.
    ///
    /// Files are stored in `~/.tsm/`:
    ///   - `ca.key` — PKCS#8 PEM private key
    ///   - `ca.crt` — PEM self-signed certificate
    pub fn load_or_create() -> Result<Arc<Self>, CaError> {
        let tsm_dir = tsm_dir()?;
        fs::create_dir_all(&tsm_dir)?;

        let key_path  = tsm_dir.join("ca.key");
        let cert_path = tsm_dir.join("ca.crt");

        let (ca_cert, ca_key, ca_cert_pem) = if key_path.exists() && cert_path.exists() {
            load_ca(&key_path, &cert_path)?
        } else {
            let (cert, key, pem) = generate_ca()?;
            fs::write(&key_path,  key.serialize_pem())?;
            fs::write(&cert_path, &pem)?;
            eprintln!(
                "[tsm-ca] Root CA generated → {}\n\
                 [tsm-ca] Install it in your OS trust store to avoid TLS errors:\n\
                 [tsm-ca]   Linux:  sudo cp {} /usr/local/share/ca-certificates/tsm-root.crt && sudo update-ca-certificates\n\
                 [tsm-ca]   macOS:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}\n\
                 [tsm-ca]   Win:    certutil -addstore Root {}",
                cert_path.display(),
                cert_path.display(),
                cert_path.display(),
                cert_path.display(),
            );
            (cert, key, pem)
        };

        Ok(Arc::new(LocalCa {
            ca_cert_pem,
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        }))
    }

    /// Return `(cert_pem, key_pem)` for a TLS leaf certificate covering `hostname`.
    ///
    /// Results are cached for `LEAF_CACHE_TTL` (1 hour).
    pub fn leaf_cert_for(&self, hostname: &str) -> Result<(Arc<String>, Arc<String>), CaError> {
        // ── Cache lookup ──────────────────────────────────────────────────────
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(hostname) {
                if !entry.is_expired() {
                    return Ok((Arc::clone(&entry.cert_pem), Arc::clone(&entry.key_pem)));
                }
            }
        }

        // ── Generate leaf ─────────────────────────────────────────────────────
        let (cert_pem, key_pem) = generate_leaf(hostname, &self.ca_cert, &self.ca_key)?;

        let entry = CacheEntry {
            cert_pem: Arc::new(cert_pem),
            key_pem:  Arc::new(key_pem),
            inserted: Instant::now(),
        };
        let cert_out = Arc::clone(&entry.cert_pem);
        let key_out  = Arc::clone(&entry.key_pem);

        // ── Cache store (evict if over cap) ───────────────────────────────────
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= LEAF_CACHE_CAP {
            cache.retain(|_, v| !v.is_expired());
            if cache.len() >= LEAF_CACHE_CAP {
                if let Some(k) = cache.keys().next().cloned() {
                    cache.remove(&k);
                }
            }
        }
        cache.insert(hostname.to_owned(), entry);

        Ok((cert_out, key_out))
    }

    /// Path to the Root CA certificate on disk (for trust-store installation).
    pub fn ca_cert_path() -> Result<PathBuf, CaError> {
        Ok(tsm_dir()?.join("ca.crt"))
    }
}

// ── Internal CA generation ────────────────────────────────────────────────────

/// Generate a new ECDSA P-256 self-signed Root CA certificate.
/// Returns `(cert, key_pair, cert_pem)`.
fn generate_ca() -> Result<(Certificate, KeyPair, String), CaError> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName,       CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORG);
    dn.push(DnType::CountryName,      CA_COUNTRY);
    params.distinguished_name = dn;

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // rcgen defaults use ECDSA P-256; explicit here for clarity
    let key_pair = KeyPair::generate()?;
    let cert     = params.self_signed(&key_pair)?;
    let pem      = cert.pem();

    Ok((cert, key_pair, pem))
}

/// Load CA certificate and private key from PEM files on disk.
fn load_ca(key_path: &Path, cert_path: &Path) -> Result<(Certificate, KeyPair, String), CaError> {
    let key_pem  = fs::read_to_string(key_path)?;
    let cert_pem = fs::read_to_string(cert_path)?;

    let key_pair  = KeyPair::from_pem(&key_pem)?;
    let ca_params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
    let ca_cert   = ca_params.self_signed(&key_pair)?;

    Ok((ca_cert, key_pair, cert_pem))
}

/// Generate a short-lived ECDSA P-256 leaf certificate for `hostname`,
/// signed by the provided CA cert + key.
fn generate_leaf(
    hostname: &str,
    ca_cert:  &Certificate,
    ca_key:   &KeyPair,
) -> Result<(String, String), CaError> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;

    // SAN is mandatory for modern TLS clients
    params.subject_alt_names = vec![SanType::DnsName(hostname.to_owned())];

    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages          = vec![KeyUsagePurpose::DigitalSignature];
    params.is_ca               = IsCa::NoCa;

    let leaf_key  = KeyPair::generate()?;
    // rcgen 0.13: signed_by(leaf_key, issuer_cert, issuer_key)
    let leaf_cert = params.signed_by(&leaf_key, ca_cert, ca_key)?;

    Ok((leaf_cert.pem(), leaf_key.serialize_pem()))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tsm_dir() -> Result<PathBuf, CaError> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| CaError::HomeDir)?;
    Ok(PathBuf::from(home).join(".tsm"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Run `f` with HOME set to a fresh temp directory, then restore.
    fn with_temp_home<F: FnOnce()>(f: F) {
        let dir = tempfile::TempDir::new().unwrap();
        // Override both HOME (Unix) and USERPROFILE (Windows) so tsm_dir() works
        env::set_var("HOME",        dir.path());
        env::set_var("USERPROFILE", dir.path());
        f();
        env::remove_var("HOME");
        env::remove_var("USERPROFILE");
    }

    #[test]
    fn ca_generates_on_first_run() {
        with_temp_home(|| {
            let ca = LocalCa::load_or_create().expect("should generate CA");
            assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"),
                    "CA cert must be PEM");
        });
    }

    #[test]
    fn ca_loads_from_disk_on_second_run() {
        with_temp_home(|| {
            let ca1 = LocalCa::load_or_create().expect("first run");
            let ca2 = LocalCa::load_or_create().expect("second run");
            assert_eq!(ca1.ca_cert_pem, ca2.ca_cert_pem,
                       "second run must load same CA cert as first");
        });
    }

    #[test]
    fn leaf_cert_for_openai() {
        with_temp_home(|| {
            let ca = LocalCa::load_or_create().unwrap();
            let (cert_pem, key_pem) = ca.leaf_cert_for("api.openai.com").unwrap();
            assert!(cert_pem.contains("BEGIN CERTIFICATE"),
                    "leaf must be a PEM cert");
            assert!(key_pem.contains("BEGIN"),
                    "leaf key must be a PEM key");
        });
    }

    #[test]
    fn leaf_cert_is_cached() {
        with_temp_home(|| {
            let ca = LocalCa::load_or_create().unwrap();
            let (c1, _) = ca.leaf_cert_for("api.anthropic.com").unwrap();
            let (c2, _) = ca.leaf_cert_for("api.anthropic.com").unwrap();
            assert!(Arc::ptr_eq(&c1, &c2),
                    "second call must return the same Arc (cache hit)");
        });
    }

    #[test]
    fn different_hostnames_get_distinct_certs() {
        with_temp_home(|| {
            let ca = LocalCa::load_or_create().unwrap();
            let (c1, _) = ca.leaf_cert_for("api.openai.com").unwrap();
            let (c2, _) = ca.leaf_cert_for("api.anthropic.com").unwrap();
            assert_ne!(*c1, *c2,
                       "distinct hostnames must produce distinct leaf certs");
        });
    }
}
