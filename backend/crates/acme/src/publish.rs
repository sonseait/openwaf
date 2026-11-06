use crate::files;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    revision: u64,
    certificates: Vec<Spec>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    hostname: String,
    cert_chain: PathBuf,
    private_key: PathBuf,
}

pub fn certificate(
    path: &Path,
    hostnames: &[String],
    retire: Option<&str>,
    chain: &[u8],
    key: &[u8],
) -> Result<u64> {
    let parsed = openssl::x509::X509::stack_from_pem(chain)?;
    validate_dns_names(parsed.first().context("missing issued leaf")?, hostnames)?;
    ensure!(
        chain.len() <= 256 * 1024 && key.len() <= 64 * 1024,
        "issued PEM exceeds TLS limits"
    );
    let parent = path.parent().context("manifest needs parent directory")?;
    files::directory(parent)?;
    // All cooperative publishers lock the same destination, including different
    // ACME accounts/state directories. Manual edits must follow the same contract.
    let _lock = files::Lock::acquire(parent.join(".openwaf-tls-writer.lock"))?;
    let original = match files::read(path, 64 * 1024, false) {
        Ok(bytes) => Some(bytes),
        Err(error) if path.try_exists()? => return Err(error),
        Err(_) => None,
    };
    let mut manifest = if let Some(bytes) = &original {
        // The current cert may already be expired; renewal must be able to
        // replace it. Validate the entire resulting batch below instead.
        serde_json::from_slice::<Manifest>(bytes).context("invalid current manifest schema")?
    } else {
        Manifest {
            schema_version: 1,
            revision: 0,
            certificates: Vec::new(),
        }
    };
    manifest.revision = manifest
        .revision
        .checked_add(1)
        .context("TLS revision exhausted")?;
    let id = files::random_id()?;
    let generation = format!("acme-{id}");
    let directory = parent.join(&generation);
    files::directory(&directory)?;
    files::write_new(&directory.join("fullchain.pem"), chain)?;
    files::write_new(&directory.join("privkey.pem"), key)?;
    files::sync_dir(&directory)?;
    manifest.certificates.retain(|entry| {
        !hostnames.iter().any(|name| {
            entry
                .hostname
                .trim_end_matches('.')
                .eq_ignore_ascii_case(name)
        }) && !retire.is_some_and(|name| {
            entry
                .hostname
                .trim_end_matches('.')
                .eq_ignore_ascii_case(name)
        })
    });
    for hostname in hostnames {
        manifest.certificates.push(Spec {
            hostname: hostname.to_owned(),
            cert_chain: PathBuf::from(&generation).join("fullchain.pem"),
            private_key: PathBuf::from(&generation).join("privkey.pem"),
        });
    }
    let bytes = serde_json::to_vec_pretty(&manifest).context("cannot encode TLS manifest")?;
    let candidate = parent.join(format!(".candidate-{id}.json"));
    files::write_new(&candidate, &bytes)?;
    let result = (|| {
        // The exact loader used by gateway validates the entire batch before
        // manifest publication. Files are immutable, so handshake does no IO.
        openwaf_tls::Store::load(&candidate)
            .context("issued certificate rejected by TLS validator")?;
        let current = if path.try_exists()? {
            Some(files::read(path, 64 * 1024, false)?)
        } else {
            None
        };
        ensure!(
            current == original,
            "TLS manifest changed during certificate preparation"
        );
        fs::rename(&candidate, path).context("cannot commit TLS manifest")?;
        files::sync_dir(parent)?;
        Ok(manifest.revision)
    })();
    if result.is_err() && candidate.exists() && fs::remove_file(&candidate).is_err() {
        eprintln!("ACME candidate cleanup failed");
    }
    // Generations are deliberately retained, including failed attempts, for
    // diagnosis/rollback. Automated GC requires version/reference tracking.
    result
}

/// Missing/expired certificate is due. Malformed input is an error, never an
/// implicit permission to create an unbounded stream of replacement orders.
pub fn renewal_leaf(path: &Path, hostname: &str) -> Result<Option<openssl::x509::X509>> {
    if !path.try_exists()? {
        return Ok(None);
    }
    let manifest: Manifest = serde_json::from_slice(&files::read(path, 64 * 1024, false)?)
        .context("invalid renewal manifest")?;
    ensure!(
        manifest.schema_version == 1 && manifest.certificates.len() <= 128,
        "invalid renewal manifest limits"
    );
    let mut entries = manifest.certificates.iter().filter(|entry| {
        entry
            .hostname
            .trim_end_matches('.')
            .eq_ignore_ascii_case(hostname)
    });
    let Some(spec) = entries.next() else {
        return Ok(None);
    };
    ensure!(entries.next().is_none(), "duplicate renewal hostname");
    let chain = openssl::x509::X509::stack_from_pem(&files::read(
        &path
            .parent()
            .context("manifest requires parent")?
            .join(&spec.cert_chain),
        256 * 1024,
        false,
    )?)?;
    ensure!(
        !chain.is_empty() && chain.len() <= 10,
        "invalid renewal chain limit"
    );
    Ok(chain.into_iter().next())
}

pub fn renewal_due(path: &Path, hostname: &str, before: u64) -> Result<bool> {
    if !path.try_exists()? {
        return Ok(true);
    }
    let manifest: Manifest = serde_json::from_slice(&files::read(path, 64 * 1024, false)?)
        .map_err(|_| anyhow::anyhow!("invalid renewal manifest"))?;
    ensure!(
        manifest.schema_version == 1 && manifest.certificates.len() <= 128,
        "invalid renewal manifest limits"
    );
    let mut entries = manifest.certificates.iter().filter(|entry| {
        entry
            .hostname
            .trim_end_matches('.')
            .eq_ignore_ascii_case(hostname)
    });
    let Some(spec) = entries.next() else {
        return Ok(true);
    };
    ensure!(entries.next().is_none(), "duplicate renewal hostname");
    let parent = path.parent().context("manifest requires parent")?;
    let chain = openssl::x509::X509::stack_from_pem(&files::read(
        &parent.join(&spec.cert_chain),
        256 * 1024,
        false,
    )?)?;
    let leaf = chain.first().context("missing renewal leaf certificate")?;
    ensure!(chain.len() <= 10, "renewal chain exceeds TLS limit");
    let now = openssl::asn1::Asn1Time::days_from_now(0)?;
    let lifetime = leaf.not_before().diff(leaf.not_after())?;
    let seconds =
        |delta: openssl::asn1::TimeDiff| i64::from(delta.days) * 86400 + i64::from(delta.secs);
    let remaining = chain
        .iter()
        .try_fold(i64::MAX, |earliest, cert| -> Result<i64> {
            Ok(earliest.min(seconds(now.diff(cert.not_after())?)))
        })?;
    // Short-lived CAs (including Pebble) must not be renewed at every check.
    let window = i64::try_from(before)?.min((seconds(lifetime) / 3).max(1));
    let due = remaining <= window;
    if !due {
        openwaf_tls::Store::load(path)
            .context("current renewal certificate failed TLS validation")?;
    }
    Ok(due)
}

/// Every requested SAN must be present, including literal wildcard identifiers.
pub fn validate_dns_names(leaf: &openssl::x509::X509Ref, names: &[String]) -> Result<()> {
    let sans = leaf
        .subject_alt_names()
        .context("certificate has no SANs")?;
    ensure!(
        !names.is_empty()
            && names.len() <= 2
            && names.iter().all(|name| sans.iter().any(|san| san
                .dnsname()
                .is_some_and(|dns| dns.eq_ignore_ascii_case(name)))),
        "certificate SANs do not match requested identifiers"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, SubjectAlternativeName},
        },
    };

    fn identity(hostname: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let name = X509NameBuilder::new()?.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let serial = BigNum::from_u32(42)?.to_asn1_integer()?;
        cert.set_serial_number(&serial)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        let before = Asn1Time::days_from_now(0)?;
        let after = Asn1Time::days_from_now(1)?;
        cert.set_not_before(&before)?;
        cert.set_not_after(&after)?;
        cert.append_extension(BasicConstraints::new().build()?)?;
        let mut san = SubjectAlternativeName::new();
        for name in hostname.split(',') {
            san.dns(name);
        }
        cert.append_extension(san.build(&cert.x509v3_context(None, None))?)?;
        cert.sign(&key, MessageDigest::sha256())?;
        Ok((cert.build().to_pem()?, key.private_key_to_pem_pkcs8()?))
    }

    #[test]
    fn apex_wildcard_migration_is_atomic_and_removes_only_retired_entry() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("tls/manifest.json");
        let old = "admin.example.test";
        let (old_chain, old_key) = identity(old)?;
        certificate(&path, &[old.into()], None, &old_chain, &old_key)?;
        let store = openwaf_tls::Store::load(&path)?;
        let names = vec!["example.test".into(), "*.example.test".into()];
        let original = fs::read(&path)?;
        assert!(certificate(&path, &names, Some(old), &old_chain, &old_key).is_err());
        assert_eq!(fs::read(&path)?, original);
        let (chain, key) = identity("example.test,*.example.test")?;
        certificate(&path, &names, Some(old), &chain, &key)?;
        store.reload(&path)?;
        let manifest: Manifest = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(manifest.certificates.len(), 2);
        assert_eq!(
            manifest.certificates[0].cert_chain,
            manifest.certificates[1].cert_chain
        );
        assert_eq!(
            store
                .certificate_for(old)
                .context("wildcard selected")?
                .hostname,
            "*.example.test"
        );
        assert!(store.certificate_for("a.b.example.test").is_none());
        assert_eq!(
            store.certificate("example.test").context("apex")?.dns_names,
            vec!["*.example.test", "example.test"]
        );
        assert!(!renewal_due(&path, "example.test", 86400)?);
        Ok(())
    }
    #[test]
    fn atomic_validation_preserves_other_hosts_and_rejects_bad_batch() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let tls = tmp.path().join("tls");
        files::directory(&tls)?;
        let path = tls.join("manifest.json");
        let (chain, key) = identity("one.example.test")?;
        assert_eq!(
            certificate(&path, &["one.example.test".into()], None, &chain, &key)?,
            1
        );
        let original = fs::read(&path)?;
        assert!(certificate(&path, &["two.example.test".into()], None, &chain, &key).is_err());
        assert_eq!(fs::read(&path)?, original);
        let (second_chain, second_key) = identity("two.example.test")?;
        assert!(
            certificate(
                &path,
                &["one.example.test".into()],
                None,
                &chain,
                &second_key
            )
            .is_err()
        );
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(
            certificate(
                &path,
                &["two.example.test".into()],
                None,
                &second_chain,
                &second_key
            )?,
            2
        );
        let manifest: Manifest = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(manifest.certificates.len(), 2);
        assert_eq!(openwaf_tls::Store::load(&path)?.revision(), 2);
        let _lock = files::Lock::acquire(tls.join(".openwaf-tls-writer.lock"))?;
        assert!(certificate(&path, &["one.example.test".into()], None, &chain, &key).is_err());
        assert_eq!(openwaf_tls::Store::load(&path)?.revision(), 2);
        Ok(())
    }
    #[test]
    fn renewal_window_handles_missing_fresh_and_malformed_certificate() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("tls/manifest.json");
        assert!(renewal_due(&path, "test.example", 86400)?);
        let (chain, key) = identity("test.example")?;
        certificate(&path, &["test.example".into()], None, &chain, &key)?;
        assert!(
            !renewal_due(&path, "test.example", 90 * 86400)?,
            "window capped to a third of lifetime"
        );
        assert!(renewal_due(&path, "missing.example", 86400)?);
        let manifest: Manifest = serde_json::from_slice(&files::read(&path, 64 * 1024, false)?)?;
        let chain_path = path
            .parent()
            .unwrap()
            .join(&manifest.certificates[0].cert_chain);
        fs::write(chain_path, b"not a certificate")?;
        assert!(renewal_due(&path, "test.example", 86400).is_err());
        Ok(())
    }
    #[test]
    fn renewal_uses_earliest_chain_expiry() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("tls/manifest.json");
        let (mut chain, key) = identity("test.example")?;
        certificate(&path, &["test.example".into()], None, &chain, &key)?;
        let leaf = X509::from_pem(&chain)?;
        let key = PKey::private_key_from_pem(&key)?;
        let mut expired = X509::builder()?;
        expired.set_version(2)?;
        let serial = BigNum::from_u32(99)?.to_asn1_integer()?;
        expired.set_serial_number(&serial)?;
        expired.set_subject_name(leaf.subject_name())?;
        expired.set_issuer_name(leaf.issuer_name())?;
        expired.set_pubkey(&key)?;
        let before = Asn1Time::from_unix(0)?;
        let after = Asn1Time::from_unix(1)?;
        expired.set_not_before(&before)?;
        expired.set_not_after(&after)?;
        expired.sign(&key, MessageDigest::sha256())?;
        chain.extend_from_slice(&expired.build().to_pem()?);
        let manifest: Manifest = serde_json::from_slice(&files::read(&path, 64 * 1024, false)?)?;
        fs::write(
            path.parent()
                .unwrap()
                .join(&manifest.certificates[0].cert_chain),
            chain,
        )?;
        assert!(
            renewal_due(&path, "test.example", 1)?,
            "an expired chain member must trigger renewal despite fresh leaf"
        );
        Ok(())
    }
}
