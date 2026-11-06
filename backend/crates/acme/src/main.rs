//! Bounded HTTP-01 / Cloudflare DNS-01 worker and renewal supervisor.
#![forbid(unsafe_code)]

mod admin;
mod ari;
mod challenge;
mod dns;
mod files;
mod http;
mod propagation;
mod publish;
mod renewal;

use anyhow::{Context, Result, ensure};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    stack::Stack,
    x509::{X509NameBuilder, X509Req, extension::SubjectAlternativeName},
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    directory_url: String,
    hostname: String,
    #[serde(default)]
    additional_dns_names: Vec<String>,
    #[serde(default)]
    retire_hostname: Option<String>,
    #[serde(default)]
    challenge_listen: Option<SocketAddr>,
    #[serde(default)]
    cloudflare: Option<dns::Config>,
    state_dir: PathBuf,
    master_key_file: PathBuf,
    tls_manifest: PathBuf,
    #[serde(default)]
    ca_pem: Option<PathBuf>,
    terms_of_service_agreed: bool,
    #[serde(default = "default_deadline")]
    deadline_seconds: u64,
    #[serde(default)]
    renewal: renewal::Settings,
}

fn default_deadline() -> u64 {
    120
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedAccount {
    directory_url: String,
    credentials: AccountCredentials,
}

impl Config {
    fn dns_names(&self) -> Vec<String> {
        std::iter::once(self.hostname.clone())
            .chain(self.additional_dns_names.clone())
            .collect()
    }
    fn renewal_due(&self) -> Result<bool> {
        for name in self.dns_names() {
            if publish::renewal_due(&self.tls_manifest, &name, self.renewal.renew_before_seconds)? {
                return Ok(true);
            }
            let leaf = publish::renewal_leaf(&self.tls_manifest, &name)?
                .context("missing renewal leaf")?;
            if publish::validate_dns_names(&leaf, &self.dns_names()).is_err() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn validate(&mut self, cleanup_only: bool) -> Result<()> {
        self.renewal.validate()?;
        let url = reqwest::Url::parse(&self.directory_url).context("invalid ACME directory URL")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "ACME directory must be HTTPS without credentials or fragment"
        );
        self.hostname = self
            .hostname
            .strip_suffix('.')
            .unwrap_or(&self.hostname)
            .to_ascii_lowercase();
        ensure!(
            self.challenge_listen.is_some() != self.cloudflare.is_some(),
            "choose exactly one of challenge_listen or cloudflare"
        );
        ensure!(
            self.additional_dns_names.len() <= 1,
            "at most two DNS identifiers supported"
        );
        ensure!(
            self.additional_dns_names.is_empty() || self.cloudflare.is_some(),
            "multi-SAN requires DNS-01"
        );
        for name in &mut self.additional_dns_names {
            *name = name.trim_end_matches('.').to_ascii_lowercase();
        }
        let names = self.dns_names();
        ensure!(
            names.len()
                == names
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
            "duplicate DNS identifier"
        );
        for hostname in &names {
            let name = if self.cloudflare.is_some() {
                hostname.strip_prefix("*.").unwrap_or(hostname)
            } else {
                hostname
            };
            ensure!(
                hostname.len() <= 253 && dns_name(name),
                "challenge requires an ASCII DNS hostname; wildcard only with DNS-01, no IP"
            );
            if let Some(cloudflare) = &mut self.cloudflare {
                cloudflare.validate(hostname)?;
            }
        }
        if let Some(retire) = &self.retire_hostname {
            ensure!(
                dns_name(retire)
                    && !names.contains(retire)
                    && names
                        .iter()
                        .any(|name| name.strip_prefix("*.").is_some_and(|base| retire
                            .strip_suffix(&format!(".{base}"))
                            .is_some_and(|label| !label.is_empty() && !label.contains('.')))),
                "retired hostname must be covered by requested wildcard"
            );
        }
        ensure!(
            (10..=180).contains(&self.deadline_seconds),
            "ACME deadline must be 10..180 seconds"
        );
        ensure!(
            cleanup_only || self.terms_of_service_agreed,
            "ACME terms must be explicitly accepted"
        );
        files::directory(&self.state_dir)?;
        ensure!(
            self.cloudflare.is_some() || !self.state_dir.join("dns-lease.enc").try_exists()?,
            "pending DNS cleanup requires Cloudflare configuration"
        );
        let key = self
            .master_key_file
            .canonicalize()
            .context("master key file is unavailable")?;
        let state = self
            .state_dir
            .canonicalize()
            .context("ACME state directory is unavailable")?;
        ensure!(
            !key.starts_with(state),
            "master key must be outside the ACME state directory"
        );
        Ok(())
    }
}

fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

async fn account(config: &Config, client: reqwest::Client) -> Result<Account> {
    let key = Zeroizing::new(files::read(&config.master_key_file, 32, true)?);
    ensure!(
        key.len() == 32,
        "master key must contain exactly 32 raw bytes"
    );
    let builder = Account::builder_with_http(Box::new(http::Transport(client)));
    let path = config.state_dir.join("account.enc");
    if path.try_exists()? {
        let bytes = files::read(&path, 64 * 1024, true)?;
        let plaintext = files::unseal(&bytes, &key)?;
        let saved: SavedAccount = serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow::anyhow!("invalid saved account schema"))?;
        ensure!(
            saved.directory_url == config.directory_url,
            "saved account belongs to a different ACME directory"
        );
        let account = builder
            .from_credentials(saved.credentials)
            .await
            .map_err(|_| anyhow::anyhow!("ACME account restore failed"))?;
        eprintln!("ACME account restored");
        return Ok(account);
    }
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory_url.clone(),
            None,
        )
        .await
        .map_err(|_| anyhow::anyhow!("ACME account registration failed"))?;
    let serialized = Zeroizing::new(
        serde_json::to_vec(&SavedAccount {
            directory_url: config.directory_url.clone(),
            credentials,
        })
        .map_err(|_| anyhow::anyhow!("ACME account serialization failed"))?,
    );
    files::write_new(&path, &files::seal(&serialized, &key)?)?;
    files::sync_dir(&config.state_dir)?;
    eprintln!("ACME account created and encrypted");
    Ok(account)
}

fn csr(hostnames: &[String]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut request = X509Req::builder()?;
    request.set_version(0)?;
    request.set_subject_name(&X509NameBuilder::new()?.build())?;
    request.set_pubkey(&key)?;
    let mut extensions = Stack::new()?;
    let mut san = SubjectAlternativeName::new();
    for hostname in hostnames {
        san.dns(hostname);
    }
    extensions.push(san.build(&request.x509v3_context(None))?)?;
    request.add_extensions(&extensions)?;
    request.sign(&key, MessageDigest::sha256())?;
    Ok((
        request.build().to_der()?,
        Zeroizing::new(key.private_key_to_pem_pkcs8()?),
    ))
}

struct Issued {
    chain: String,
    key: Zeroizing<Vec<u8>>,
}

fn stage(name: &str, status: &str) {
    eprintln!("OWAF_STAGE {name} {status}");
}

async fn issue(
    config: &Config,
    active: challenge::Active,
    mut dns: Option<&mut dns::Cloudflare>,
) -> Result<Issued> {
    let _registration = challenge::Registration(active.clone());
    stage("dns_cleanup", "started");
    // Recover any previous ambiguous/cancelled order before creating another.
    if let Some(provider) = &mut dns {
        provider
            .cleanup()
            .await
            .context("pending DNS cleanup failed")?;
        stage("dns_cleanup", "ok");
    }
    stage("account", "started");
    let client = http::client(config.ca_pem.as_deref())?;
    let account = account(config, client).await?;
    stage("account", "ok");
    stage("order", "started");
    let identifiers: Vec<_> = config
        .dns_names()
        .into_iter()
        .map(Identifier::Dns)
        .collect();
    let mut request = NewOrder::new(&identifiers);
    // Unsupported/unavailable ARI must not prevent ordinary expiry renewal.
    let replacement = ari::replacement(config, &account).await?;
    let replacing = replacement.is_some();
    if let Some(id) = replacement {
        request = request.replaces(id);
    }
    let result = account.new_order(&request).await;
    // Only a definitive rejection permits one ordinary-order fallback. Never
    // retry ambiguous transport failures, quota errors or general server errors.
    let result = match result {
        Err(error) if replacing && ari::replacement_rejected(&error) => {
            eprintln!("ACME ARI: replacement rejected; requesting ordinary order");
            account.new_order(&NewOrder::new(&identifiers)).await
        }
        result => result,
    };
    let mut order = result.map_err(|_| anyhow::anyhow!("ACME order creation failed"))?;
    stage("order", "ok");
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization =
            result.map_err(|_| anyhow::anyhow!("ACME authorization fetch failed"))?;
        let identifier = authorization.identifier().to_string();
        ensure!(
            config.dns_names().contains(&identifier),
            "ACME authorization identifier does not match requested names"
        );
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            _ => anyhow::bail!("ACME authorization is invalid"),
        }
        let kind = if dns.is_some() {
            ChallengeType::Dns01
        } else {
            ChallengeType::Http01
        };
        let mut challenge = authorization
            .challenge(kind)
            .context("ACME server did not offer requested challenge")?;
        ensure!(
            challenge.identifier().to_string() == identifier,
            "ACME authorization identifier does not match requested hostname"
        );
        ensure!(
            !challenge.token.is_empty()
                && challenge.token.len() <= 256
                && challenge
                    .token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid ACME challenge token"
        );
        if let Some(provider) = &mut dns {
            stage("dns_present", "started");
            provider
                .present(&identifier, &challenge.key_authorization().dns_value())
                .await?;
            stage("dns_present", "ok");
            stage("dns_propagation", "started");
            if let Err(error) = provider.wait_propagation().await {
                stage("dns_propagation", "failed");
                return Err(error);
            }
            stage("dns_propagation", "ok");
        } else {
            active.store(Some(Arc::new(challenge::Challenge {
                hostname: config.hostname.clone(),
                token: challenge.token.clone(),
                value: challenge.key_authorization().as_str().to_owned(),
            })));
            eprintln!("ACME HTTP-01 challenge registered");
        }
        challenge
            .set_ready()
            .await
            .map_err(|_| anyhow::anyhow!("ACME challenge activation failed"))?;
    }
    let retries = RetryPolicy::new()
        .initial_delay(Duration::from_millis(250))
        .backoff(1.5)
        .timeout(Duration::from_secs(60));
    stage("ca_validation", "started");
    let status = order
        .poll_ready(&retries)
        .await
        .map_err(|_| anyhow::anyhow!("ACME validation failed or timed out"))?;
    ensure!(
        status == OrderStatus::Ready,
        "ACME order not ready after validation"
    );
    stage("ca_validation", "ok");
    active.store(None);
    stage("finalize", "started");
    let (request, key) = csr(&config.dns_names())
        .map_err(|_| anyhow::anyhow!("certificate key/CSR generation failed"))?;
    order
        .finalize_csr(&request)
        .await
        .map_err(|_| anyhow::anyhow!("ACME order finalization failed"))?;
    stage("finalize", "ok");
    stage("certificate", "started");
    let chain = order
        .poll_certificate(&retries)
        .await
        .map_err(|_| anyhow::anyhow!("ACME certificate retrieval failed or timed out"))?;
    stage("certificate", "ok");
    Ok(Issued { chain, key })
}

async fn interrupted() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = term.recv() => {} }
    Ok(())
}

async fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().context(
        "usage: openwaf-acme [cleanup-dns|watch] CONFIG.json OR watch-many CONFIG.json...",
    )?;
    if first == "watch-many" {
        let paths = args.map(PathBuf::from).collect::<Vec<_>>();
        return renewal::watch_many(paths).await;
    }
    let renew_once = first == "renew-once";
    let cleanup_only = first == "cleanup-dns";
    let watch = first == "watch";
    let path = if cleanup_only || watch || renew_once {
        args.next().context("command requires CONFIG.json")?
    } else {
        first
    };
    ensure!(
        args.next().is_none(),
        "usage: openwaf-acme [cleanup-dns|watch] CONFIG.json OR watch-many CONFIG.json..."
    );
    let bytes = files::read(&PathBuf::from(path), 64 * 1024, false)?;
    let mut config: Config = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid ACME config schema"))?;
    stage("input", "started");
    config.validate(cleanup_only)?;
    stage("input", "ok");
    ensure!(
        !cleanup_only || config.cloudflare.is_some(),
        "cleanup-dns requires Cloudflare configuration"
    );
    if watch {
        return renewal::watch(config, &bytes).await;
    }
    if renew_once && !config.renewal_due()? {
        return Ok(());
    }
    let _lock = files::Lock::acquire(config.state_dir.join(".writer.lock"))?;
    let server = if let Some(address) = config.challenge_listen {
        Some(challenge::Server::start(address).await?)
    } else {
        None
    };
    let active = server
        .as_ref()
        .map(|server| server.active.clone())
        .unwrap_or_else(|| Arc::new(arc_swap::ArcSwapOption::empty()));
    let mut dns = config
        .cloudflare
        .as_ref()
        .map(|provider| dns::Cloudflare::open(provider, &config.state_dir, &config.master_key_file))
        .transpose()?;
    let operation = async {
        if cleanup_only {
            dns.as_mut()
                .context("DNS provider missing")?
                .cleanup()
                .await?;
            Ok(None)
        } else {
            issue(&config, active, dns.as_mut()).await.map(Some)
        }
    };
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(config.deadline_seconds), operation) => match result {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("ACME overall deadline exceeded")),
        },
        result = interrupted() => result.and_then(|()| Err(anyhow::anyhow!("ACME cancelled by signal"))),
    };
    if let Some(server) = server {
        server.shutdown().await?;
    }
    // Cleanup is owned outside the cancelled order future and gets a separate
    // bounded deadline. No certificate publication until cleanup is acknowledged.
    if let Some(provider) = &mut dns {
        stage("dns_cleanup", "started");
        let cleanup = tokio::time::timeout(Duration::from_secs(20), provider.cleanup())
            .await
            .context("DNS cleanup deadline exceeded; journal retained")
            .and_then(|result| result.context("DNS cleanup incomplete; journal retained"));
        if cleanup.is_ok() {
            stage("dns_cleanup", "ok");
        }
        if let Err(error) = cleanup {
            if let Err(order_error) = &result {
                eprintln!("ACME order failed: {order_error:#}");
            }
            return Err(error);
        }
    }
    let Some(issued) = result? else {
        eprintln!("DNS cleanup checked; no ACME order created");
        return Ok(());
    };
    stage("publish", "started");
    let revision = publish::certificate(
        &config.tls_manifest,
        &config.dns_names(),
        config.retire_hostname.as_deref(),
        issued.chain.as_bytes(),
        &issued.key,
    )?;
    stage("publish", "ok");
    eprintln!("ACME certificate committed at TLS revision {revision}");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "admin-start" || arg == "admin-health")
    {
        let result = if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == "admin-health")
        {
            admin::health()
        } else {
            admin::start().await
        };
        if let Err(error) = result {
            eprintln!("Admin TLS bootstrap: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    let result = if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "seal-cloudflare-token" || arg == "seal-bootstrap-provider")
    {
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == "seal-bootstrap-provider")
        {
            provision_provider()
        } else {
            provision_token()
        }
    } else {
        run().await
    };
    if let Err(error) = result {
        eprintln!("ACME: {error:#}");
        std::process::exit(1);
    }
}

fn provision_token() -> Result<()> {
    let args = std::env::args_os()
        .skip(2)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    ensure!(
        args.len() == 3,
        "usage: openwaf-acme seal-cloudflare-token INPUT OUTPUT MASTER_KEY"
    );
    let bytes = Zeroizing::new(files::read(&args[0], 1024, true)?);
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid Cloudflare token encoding"))?
        .trim();
    dns::validate_token(token.as_bytes())?;
    let key = Zeroizing::new(files::read(&args[2], 32, true)?);
    let parent = args[1]
        .parent()
        .context("token output requires parent directory")?;
    files::directory(parent)?;
    let canonical_parent = parent.canonicalize()?;
    ensure!(
        !args[2].canonicalize()?.starts_with(canonical_parent),
        "master key must be outside token output directory"
    );
    files::write_new(
        &args[1],
        &files::seal_kind(token.as_bytes(), &key, files::SecretKind::CloudflareToken)?,
    )?;
    files::sync_dir(parent)?;
    eprintln!("Cloudflare token encrypted");
    Ok(())
}

fn provision_provider() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(2).collect();
    ensure!(
        args.len() == 4,
        "usage: seal-bootstrap-provider INPUT OUTPUT ADMIN_KEY HOSTNAME"
    );
    let hostname = args[3].to_str().context("invalid bootstrap hostname")?;
    ensure!(dns_name(hostname), "invalid bootstrap hostname");
    let bytes = Zeroizing::new(files::read(PathBuf::from(&args[0]).as_path(), 1024, true)?);
    let token = std::str::from_utf8(&bytes)
        .context("invalid token encoding")?
        .trim();
    dns::validate_token(token.as_bytes())?;
    let credentials = openwaf_cloudflare::Credentials {
        auth_type: "api_token".into(),
        secret: token.into(),
        email: None,
    };
    let plain = Zeroizing::new(serde_json::to_vec(&credentials)?);
    let key = Zeroizing::new(files::read(PathBuf::from(&args[2]).as_path(), 32, true)?);
    ensure!(key.len() == 32, "invalid Admin master key");
    let mut nonce = [0; 12];
    let mut tag = [0; 16];
    openssl::rand::rand_bytes(&mut nonce)?;
    let aad = format!("openwaf-admin-secret-v1:bootstrap-cloudflare:{hostname}");
    let ciphertext = openssl::symm::encrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        aad.as_bytes(),
        &plain,
        &mut tag,
    )?;
    let path = PathBuf::from(&args[1]);
    files::write_new(
        &path,
        &[b"OWAD1".as_slice(), &nonce, &tag, &ciphertext].concat(),
    )?;
    files::sync_dir(path.parent().context("seed output requires parent")?)
}
