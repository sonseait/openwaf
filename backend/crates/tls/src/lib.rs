//! Validated certificate snapshots. No filesystem access on the handshake path.
#![forbid(unsafe_code)]

use arc_swap::ArcSwap;
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    pkey::{PKey, Private},
    ssl::{
        NameType, SniError, SslAcceptor, SslAcceptorBuilder, SslAlert, SslMethod, SslOptions,
        SslSessionCacheMode, SslVersion,
    },
    stack::Stack,
    x509::{
        X509, X509PurposeId, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyFlags,
    },
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_MANIFEST: usize = 64 * 1024;
const MAX_CHAIN: usize = 256 * 1024;
const MAX_KEY: usize = 64 * 1024;
const MAX_IDENTITIES: usize = 128;
const MAX_CHAIN_LENGTH: usize = 10;

/// Errors intentionally omit PEM, key bytes, parser input and native error stacks.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("cannot read TLS input as a bounded regular file")]
    Read,
    #[error("TLS private key file must be accessible only by its owner")]
    KeyPermissions,
    #[error("invalid TLS manifest schema or limits")]
    Manifest,
    #[error("TLS revision must increase; existing revisions are immutable")]
    Revision,
    #[error("invalid or duplicate TLS hostname; use ASCII DNS names/punycode")]
    Hostname,
    #[error("invalid certificate PEM or chain")]
    Certificate,
    #[error("certificate not currently valid")]
    Validity,
    #[error("certificate SAN does not cover configured hostname")]
    Coverage,
    #[error("invalid private key or certificate/key mismatch")]
    PrivateKey,
    #[error("cannot configure TLS acceptor")]
    Acceptor,
    #[error("TLS reload coordinator unavailable")]
    Coordinator,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    revision: u64,
    certificates: Vec<CertificateSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateSpec {
    hostname: String,
    cert_chain: PathBuf,
    private_key: PathBuf,
}

struct Identity {
    chain: Vec<X509>,
    key: PKey<Private>,
    valid_from: i64,
    valid_until: i64,
}

/// Public certificate metadata only; never exposes PEM paths, keys or ACME credentials.
#[derive(serde::Serialize)]
pub struct CertificateStatus {
    pub hostname: String,
    pub dns_names: Vec<String>,
    pub valid_from_unix_s: i64,
    pub valid_until_unix_s: i64,
}

struct Snapshot {
    revision: u64,
    manifest_bytes: Vec<u8>,
    identities: HashMap<String, Identity>,
}

impl Snapshot {
    fn select(&self, hostname: &str, now: i64) -> Option<&Identity> {
        self.selected(hostname, now).map(|(_, identity)| identity)
    }

    fn selected(&self, hostname: &str, now: i64) -> Option<(&String, &Identity)> {
        let name = normalize_name(hostname, false).ok()?;
        // An exact entry wins even when expired: never silently substitute it.
        let (key, identity) = self.identities.get_key_value(&name).or_else(|| {
            let (_, suffix) = name.split_once('.')?;
            self.identities.get_key_value(&format!("*.{suffix}"))
        })?;
        (identity.valid_from <= now && now < identity.valid_until).then_some((key, identity))
    }
}

fn status(hostname: &str, identity: &Identity) -> CertificateStatus {
    CertificateStatus {
        hostname: hostname.to_owned(),
        dns_names: identity.chain[0]
            .subject_alt_names()
            .map(|sans| {
                let mut names: Vec<_> = sans
                    .iter()
                    .filter_map(|san| {
                        san.dnsname()
                            .and_then(|name| normalize_name(name, true).ok())
                    })
                    .collect();
                names.sort();
                names.dedup();
                names
            })
            .unwrap_or_default(),
        valid_from_unix_s: identity.valid_from,
        valid_until_unix_s: identity.valid_until,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reload {
    Unchanged,
    Applied { revision: u64, certificates: usize },
}

/// Reloads are serialized off the handshake path. Readers only load an immutable
/// Arc; every key/cert/chain is prepared before a single atomic publication.
pub struct Store {
    active: ArcSwap<Snapshot>,
    reload: Mutex<()>,
}

impl Store {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let store = Self {
            active: ArcSwap::from_pointee(Snapshot {
                revision: 0,
                manifest_bytes: Vec::new(),
                identities: HashMap::new(),
            }),
            reload: Mutex::new(()),
        };
        store.reload(path)?;
        Ok(store)
    }

    /// Manifest is the commit marker. Write immutable PEM files first, then
    /// atomically replace the manifest with a greater revision, also for rollback.
    /// In-place PEM edits with an unchanged manifest are deliberately ignored.
    pub fn reload(&self, path: &Path) -> Result<Reload, Error> {
        let _reload = self.reload.lock().map_err(|_| Error::Coordinator)?;
        let bytes = read_regular(path, MAX_MANIFEST, false)?;
        let current = self.active.load_full();
        if bytes == current.manifest_bytes {
            return Ok(Reload::Unchanged);
        }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| Error::Manifest)?;
        if manifest.schema_version != 1
            || manifest.revision == 0
            || manifest.certificates.len() > MAX_IDENTITIES
        {
            return Err(Error::Manifest);
        }
        if manifest.revision <= current.revision {
            return Err(Error::Revision);
        }
        let base = path.parent().ok_or(Error::Manifest)?;
        let mut identities = HashMap::new();
        let now = unix_now().ok_or(Error::Validity)?;
        for spec in manifest.certificates {
            let name = normalize_name(&spec.hostname, true)?;
            if identities.contains_key(&name) {
                return Err(Error::Hostname);
            }
            let chain_bytes = read_regular(&base.join(spec.cert_chain), MAX_CHAIN, false)?;
            let key_bytes =
                Zeroizing::new(read_regular(&base.join(spec.private_key), MAX_KEY, true)?);
            let chain = X509::stack_from_pem(&chain_bytes).map_err(|_| Error::Certificate)?;
            if chain.is_empty() || chain.len() > MAX_CHAIN_LENGTH {
                return Err(Error::Certificate);
            }
            let key = PKey::private_key_from_pem_passphrase(&key_bytes, b"")
                .map_err(|_| Error::PrivateKey)?;
            let public = chain[0].public_key().map_err(|_| Error::Certificate)?;
            if !public.public_eq(&key) {
                return Err(Error::PrivateKey);
            }
            validate_coverage(&chain[0], &name)?;
            let mut valid_from = i64::MIN;
            let mut valid_until = i64::MAX;
            for certificate in &chain {
                valid_from = valid_from.max(unix_time(certificate.not_before())?);
                valid_until = valid_until.min(unix_time(certificate.not_after())?);
            }
            if !(valid_from <= now && now < valid_until) {
                return Err(Error::Validity);
            }
            validate_chain(&chain)?;
            identities.insert(
                name,
                Identity {
                    chain,
                    key,
                    valid_from,
                    valid_until,
                },
            );
        }
        let applied = Reload::Applied {
            revision: manifest.revision,
            certificates: identities.len(),
        };
        self.active.store(Arc::new(Snapshot {
            revision: manifest.revision,
            manifest_bytes: bytes,
            identities,
        }));
        Ok(applied)
    }

    pub fn revision(&self) -> u64 {
        self.active.load().revision
    }

    /// Currently usable certificate selected exactly as for a concrete SNI hostname.
    pub fn certificate_for(&self, hostname: &str) -> Option<CertificateStatus> {
        let snapshot = self.active.load();
        let (key, identity) = snapshot.selected(hostname, unix_now()?)?;
        Some(status(key, identity))
    }

    /// Currently valid exact manifest entry, including wildcard keys. This does
    /// not perform SNI matching or accept wildcard names in TLS handshakes.
    pub fn certificate(&self, hostname: &str) -> Option<CertificateStatus> {
        let name = normalize_name(hostname, true).ok()?;
        let snapshot = self.active.load();
        let identity = snapshot.identities.get(&name)?;
        let now = unix_now()?;
        (identity.valid_from <= now && now < identity.valid_until).then(|| status(&name, identity))
    }

    pub fn certificates(&self) -> Vec<CertificateStatus> {
        let snapshot = self.active.load();
        let mut statuses: Vec<_> = snapshot
            .identities
            .iter()
            .map(|(hostname, identity)| status(hostname, identity))
            .collect();
        statuses.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        statuses
    }

    pub fn acceptor(self: &Arc<Self>) -> Result<SslAcceptorBuilder, Error> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .map_err(|_| Error::Acceptor)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| Error::Acceptor)?;
        builder.set_options(SslOptions::NO_TICKET | SslOptions::NO_RENEGOTIATION);
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder.set_num_tickets(0).map_err(|_| Error::Acceptor)?;
        let store = self.clone();
        builder.set_servername_callback(move |ssl, alert| {
            *alert = SslAlert::UNRECOGNIZED_NAME;
            let sni = ssl
                .servername(NameType::HOST_NAME)
                .ok_or(SniError::ALERT_FATAL)?;
            let snapshot = store.active.load();
            let identity = snapshot
                .select(sni, unix_now().ok_or(SniError::ALERT_FATAL)?)
                .ok_or(SniError::ALERT_FATAL)?;
            ssl.set_certificate(&identity.chain[0])
                .map_err(|_| SniError::ALERT_FATAL)?;
            ssl.set_private_key(&identity.key)
                .map_err(|_| SniError::ALERT_FATAL)?;
            for intermediate in &identity.chain[1..] {
                ssl.add_chain_cert(intermediate.clone())
                    .map_err(|_| SniError::ALERT_FATAL)?;
            }
            Ok(())
        });
        // No default cert on the context: missing/unknown SNI can never fall back.
        // Resumption is off so all new connections pass the selection/expiry gate.
        Ok(builder)
    }
}

fn read_regular(path: &Path, max: usize, private: bool) -> Result<Vec<u8>, Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK); // Reject FIFO/device input without blocking open.
    }
    let file = options.open(path).map_err(|_| Error::Read)?;
    let metadata = file.metadata().map_err(|_| Error::Read)?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(Error::Read);
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::KeyPermissions);
        }
    }
    let mut bytes = Vec::new();
    file.take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Read)?;
    if bytes.len() > max {
        return Err(Error::Read);
    }
    Ok(bytes)
}

fn unix_now() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .try_into()
        .ok()
}

fn unix_time(time: &Asn1TimeRef) -> Result<i64, Error> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| Error::Validity)?;
    let difference = epoch.diff(time).map_err(|_| Error::Validity)?;
    Ok(i64::from(difference.days) * 86400 + i64::from(difference.secs))
}

fn normalize_name(input: &str, wildcard: bool) -> Result<String, Error> {
    let name = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.is_ascii() || name.parse::<IpAddr>().is_ok() {
        return Err(Error::Hostname);
    }
    let dns = if let Some(suffix) = name.strip_prefix("*.") {
        if !wildcard || !suffix.contains('.') {
            return Err(Error::Hostname);
        }
        suffix
    } else {
        &name
    };
    if dns.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err(Error::Hostname);
    }
    Ok(name)
}

fn covered_by(name: &str, san: &str) -> bool {
    if name == san {
        return true;
    }
    if name.starts_with("*.") {
        return false;
    }
    san.strip_prefix("*.")
        .and_then(|suffix| name.strip_suffix(&format!(".{suffix}")))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

fn validate_coverage(leaf: &X509, name: &str) -> Result<(), Error> {
    let covers = leaf.subject_alt_names().is_some_and(|sans| {
        sans.iter().any(|san| {
            san.dnsname()
                .and_then(|dns| normalize_name(dns, true).ok())
                .is_some_and(|san| covered_by(name, &san))
        })
    });
    if covers { Ok(()) } else { Err(Error::Coverage) }
}

// Validate chain order/signatures and SSL-server purpose using the supplied last
// cert as an explicit private trust anchor. This does NOT establish public trust;
// clients must verify against their own trust roots. Leaf-only private certs work.
fn validate_chain(chain: &[X509]) -> Result<(), Error> {
    for pair in chain.windows(2) {
        let issuer = pair[1].public_key().map_err(|_| Error::Certificate)?;
        if pair[0]
            .issuer_name()
            .to_der()
            .map_err(|_| Error::Certificate)?
            != pair[1]
                .subject_name()
                .to_der()
                .map_err(|_| Error::Certificate)?
            || !pair[0].verify(&issuer).map_err(|_| Error::Certificate)?
        {
            return Err(Error::Certificate);
        }
    }
    let mut trust = X509StoreBuilder::new().map_err(|_| Error::Certificate)?;
    trust
        .add_cert(chain[chain.len() - 1].clone())
        .map_err(|_| Error::Certificate)?;
    trust
        .set_flags(X509VerifyFlags::PARTIAL_CHAIN | X509VerifyFlags::CHECK_SS_SIGNATURE)
        .map_err(|_| Error::Certificate)?;
    trust
        .set_purpose(X509PurposeId::SSL_SERVER)
        .map_err(|_| Error::Certificate)?;
    let mut intermediates = Stack::new().map_err(|_| Error::Certificate)?;
    for certificate in &chain[1..] {
        intermediates
            .push(certificate.clone())
            .map_err(|_| Error::Certificate)?;
    }
    let valid = X509StoreContext::new()
        .map_err(|_| Error::Certificate)?
        .init(&trust.build(), &chain[0], &intermediates, |ctx| {
            ctx.verify_cert()
        })
        .map_err(|_| Error::Certificate)?;
    if valid {
        Ok(())
    } else {
        Err(Error::Certificate)
    }
}
