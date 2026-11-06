//! ARI can advance renewal; it never postpones the local expiry safety window.
//! Cache is bounded to one certificate per owned supervisor. Stable certificate
//! hashing spreads renewals within a window and survives scheduler restarts.
use crate::{Config, account, files, http, publish};
use anyhow::{Context, Result, ensure};
use instant_acme::{Account, CertificateIdentifier};
use rustls_pki_types::CertificateDer;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn identifier(config: &Config) -> Result<Option<CertificateIdentifier<'static>>> {
    let Some(leaf) = publish::renewal_leaf(&config.tls_manifest, &config.hostname)? else {
        return Ok(None);
    };
    let der = CertificateDer::from(leaf.to_der()?);
    Ok(Some(
        CertificateIdentifier::try_from(&der)
            .map_err(|_| anyhow::anyhow!("certificate has no ARI identifier"))?
            .into_owned(),
    ))
}

fn selection(id: &str, start: i64, end: i64, now: i64) -> Result<i64> {
    let width = end.checked_sub(start).context("invalid ARI window")?;
    ensure!(
        (1..=90 * 86400).contains(&width) && start <= now.saturating_add(180 * 86400),
        "invalid ARI window bounds"
    );
    let hash = openssl::sha::sha256(id.as_bytes());
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&hash[..8]);
    Ok(start + (u64::from_be_bytes(prefix) % u64::try_from(width)?) as i64)
}

pub fn replacement_rejected(error: &instant_acme::Error) -> bool {
    matches!(error, instant_acme::Error::Api(problem) if matches!(
        (problem.status, problem.r#type.as_deref()),
        (Some(403), Some("urn:ietf:params:acme:error:unauthorized"))
        | (Some(409), Some("urn:ietf:params:acme:error:malformed"))
        | (Some(400 | 409), Some("urn:ietf:params:acme:error:alreadyReplaced"))
    ))
}

async fn info(account: &Account, id: &CertificateIdentifier<'_>) -> Result<(i64, Duration)> {
    let (info, retry) = account
        .renewal_info(id)
        .await
        .map_err(|_| anyhow::anyhow!("ARI unsupported or unavailable"))?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok((
        selection(
            &id.to_string(),
            info.suggested_window.start.unix_timestamp(),
            info.suggested_window.end.unix_timestamp(),
            now,
        )?,
        retry.clamp(Duration::from_secs(60), Duration::from_secs(86400)),
    ))
}

#[derive(Default)]
pub struct Schedule {
    cached: Option<(String, Instant, Option<i64>)>,
}
impl Schedule {
    pub async fn due(&mut self, config: &Config) -> bool {
        // Inspection never registers accounts. A missing AKI is a safe fallback,
        // for example for imported self-signed certificates.
        let id = match identifier(config) {
            Ok(Some(id)) => id,
            _ => return false,
        };
        let key = id.to_string();
        if !self
            .cached
            .as_ref()
            .is_some_and(|(old, until, _)| old == &key && *until > Instant::now())
        {
            let result = tokio::time::timeout(Duration::from_secs(20), async {
                ensure!(
                    config.state_dir.join("account.enc").try_exists()?,
                    "no saved ARI account"
                );
                let account = account(config, http::client(config.ca_pem.as_deref())?).await?;
                info(&account, &id).await
            })
            .await;
            let (selected, retry) = match result {
                Ok(Ok((selected, retry))) => {
                    eprintln!("ACME ARI: renewal window accepted");
                    (Some(selected), retry)
                }
                _ => {
                    eprintln!("ACME ARI: unavailable; using expiry schedule");
                    (None, Duration::from_secs(300))
                }
            };
            self.cached = Some((key, Instant::now() + retry, selected));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok());
        matches!((&self.cached, now), (Some((_, _, Some(selected))), Some(now)) if now >= *selected)
    }
}

pub async fn replacement(
    config: &Config,
    account: &Account,
) -> Result<Option<CertificateIdentifier<'static>>> {
    let Some(id) = identifier(config).ok().flatten() else {
        return Ok(None);
    };
    // Caller holds the issuance writer lock. Commit intent before the network
    // operation: CA acceptance/finalization may precede a failed DNS cleanup or
    // lost response. Never submit `replaces` twice for that certificate, even
    // across restart. Subsequent attempts use ordinary bounded issuance.
    let path = config.state_dir.join("ari-replacement.enc");
    let fingerprint = openssl::sha::sha256(id.to_string().as_bytes());
    let key = zeroize::Zeroizing::new(files::read(&config.master_key_file, 32, true)?);
    let mut attempted = zeroize::Zeroizing::new(Vec::new());
    if path.try_exists()? {
        let bytes = files::read(&path, 8192, true)?;
        attempted = files::unseal_kind(&bytes, &key, files::SecretKind::AriReplacement)?;
        ensure!(
            !attempted.is_empty() && attempted.len() % 32 == 0 && attempted.len() <= 4096,
            "invalid ARI replacement state"
        );
        if attempted.as_chunks::<32>().0.contains(&fingerprint) {
            return Ok(None);
        }
        if attempted.len() == 4096 {
            eprintln!("ACME ARI: replacement history full; using ordinary issuance");
            return Ok(None);
        }
    }
    match tokio::time::timeout(Duration::from_secs(5), info(account, &id)).await {
        Ok(Ok(_)) => {
            attempted.extend_from_slice(&fingerprint);
            files::replace_secret(
                &path,
                &files::seal_kind(&attempted, &key, files::SecretKind::AriReplacement)?,
            )?;
            eprintln!("ACME ARI: replacing previous certificate");
            Ok(Some(id))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_is_stable_bounded_and_rejects_bad_windows() -> Result<()> {
        let selected = selection("aki.serial", 100, 200, 100)?;
        assert!((100..200).contains(&selected));
        assert_eq!(selection("aki.serial", 100, 200, 150)?, selected);
        assert!(selection("aki.serial", 200, 100, 100).is_err());
        assert!(selection("aki.serial", 100, 100, 100).is_err());
        assert!(selection("aki.serial", 100, 100 + 91 * 86400, 100).is_err());
        assert!(selection("aki.serial", 200 * 86400, 200 * 86400 + 1, 100).is_err());
        assert!(selection("aki.serial", i64::MIN, i64::MAX, 100).is_err());
        Ok(())
    }
    #[test]
    fn only_definitive_replacement_rejections_allow_one_fallback() {
        for (status, kind, expected) in [
            (403, "unauthorized", true),
            (409, "malformed", true),
            (400, "alreadyReplaced", true),
            (429, "rateLimited", false),
            (500, "serverInternal", false),
            (400, "malformed", false),
        ] {
            let error = instant_acme::Error::Api(instant_acme::Problem {
                status: Some(status),
                r#type: Some(format!("urn:ietf:params:acme:error:{kind}")),
                detail: None,
                subproblems: vec![],
            });
            assert_eq!(replacement_rejected(&error), expected);
        }
        assert!(!replacement_rejected(&instant_acme::Error::Str(
            "transport failed"
        )));
    }

    #[test]
    fn certificate_id_preserves_der_serial_sign_padding() -> Result<()> {
        use openssl::{
            asn1::Asn1Time,
            bn::BigNum,
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            x509::{
                X509, X509NameBuilder,
                extension::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
            },
        };
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let serial = BigNum::from_u32(128)?.to_asn1_integer()?;
        cert.set_serial_number(&serial)?;
        let name = X509NameBuilder::new()?.build();
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        let before = Asn1Time::days_from_now(0)?;
        let after = Asn1Time::days_from_now(1)?;
        cert.set_not_before(&before)?;
        cert.set_not_after(&after)?;
        cert.append_extension(
            SubjectKeyIdentifier::new().build(&cert.x509v3_context(None, None))?,
        )?;
        cert.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&cert.x509v3_context(None, None))?,
        )?;
        cert.sign(&key, MessageDigest::sha256())?;
        let der = CertificateDer::from(cert.build().to_der()?);
        let id = CertificateIdentifier::try_from(&der).map_err(anyhow::Error::msg)?;
        assert_eq!(id.serial, "AIA"); // DER INTEGER value 00 80, not stripped 80.
        Ok(())
    }
}
