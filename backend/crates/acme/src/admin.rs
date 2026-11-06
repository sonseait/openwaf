//! Startup DNS/certificate owner for the single public admin hostname.
//! Runs in a separate service, never on a Pingora request/runtime.
use crate::files;
use anyhow::{Context, Result, ensure};
use openwaf_cloudflare::{ApiError, Client};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;
use zeroize::Zeroizing;

mod provision_dns;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    hostname: String,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    proxied: bool,
    tls_manifest: PathBuf,
}
#[derive(Serialize, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

fn root() -> PathBuf {
    std::env::var_os("OPENWAF_ADMIN_BOOTSTRAP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/var/lib/openwaf-admin-bootstrap".into())
}
fn settings(root: &Path) -> Result<Settings> {
    let value: Settings =
        serde_json::from_slice(&files::read(&root.join("admin.json"), 8192, true)?)
            .map_err(|_| anyhow::anyhow!("invalid admin bootstrap settings"))?;
    ensure!(
        crate::dns_name(&value.hostname)
            && !value.hostname.starts_with("*.")
            && value.hostname.split('.').count() <= 16
            && (value.ipv4.is_some() || value.ipv6.is_some()),
        "admin bootstrap requires an exact hostname and explicit origin IP"
    );
    ensure!(
        value
            .ipv4
            .is_none_or(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback())
            && value
                .ipv6
                .is_none_or(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()),
        "invalid origin IP"
    );
    Ok(value)
}
fn valid(settings: &Settings) -> bool {
    openwaf_tls::Store::load(&settings.tls_manifest)
        .ok()
        .and_then(|store| store.certificate_for(&settings.hostname))
        .is_some()
}
fn bundle_valid(root: &Path, settings: &Settings) -> Result<bool> {
    if !root.join("zone.json").try_exists()? {
        return Ok(false);
    }
    let zone: Zone = serde_json::from_slice(&files::read(&root.join("zone.json"), 1024, true)?)?;
    validate_zone(settings, &zone)?;
    let Ok(store) = openwaf_tls::Store::load(&settings.tls_manifest) else {
        return Ok(false);
    };
    let names = [zone.name.clone(), format!("*.{}", zone.name)];
    Ok(names.iter().all(|name| {
        store
            .certificate(name)
            .is_some_and(|cert| names.iter().all(|name| cert.dns_names.contains(name)))
    }))
}

fn contains_hostname(settings: &Settings) -> Result<bool> {
    if !settings.tls_manifest.try_exists()? {
        return Ok(false);
    }
    let value: Value = serde_json::from_slice(&files::read(&settings.tls_manifest, 65536, true)?)?;
    Ok(value["certificates"]
        .as_array()
        .context("invalid TLS manifest")?
        .iter()
        .any(|entry| {
            entry["hostname"].as_str().is_some_and(|name| {
                name.trim_end_matches('.')
                    .eq_ignore_ascii_case(&settings.hostname)
            })
        }))
}
fn master_key() -> PathBuf {
    std::env::var_os("OPENWAF_ADMIN_ACME_KEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/run/openwaf-acme-key/master.key".into())
}
fn credentials(root: &Path) -> Result<openwaf_cloudflare::Credentials> {
    let key = Zeroizing::new(files::read(&master_key(), 32, true)?);
    openwaf_cloudflare::open(
        &files::read(&root.join("providers/cloudflare.enc"), 4096, true)?,
        &key,
    )
}
async fn api(
    client: &Client,
    method: Method,
    path: &str,
    query: &[(&str, String)],
    body: Option<&Value>,
) -> Result<Value> {
    client
        .call(method, path, query, body)
        .await
        .map_err(|code| anyhow::anyhow!("admin Cloudflare API: {code:?}"))
}
fn validate_zone(settings: &Settings, zone: &Zone) -> Result<()> {
    let child = settings.hostname.strip_suffix(&format!(".{}", zone.name));
    ensure!(
        settings.hostname == zone.name
            || child.is_some_and(|label| !label.is_empty() && !label.contains('.')),
        "admin hostname must be the Cloudflare zone or one direct subdomain"
    );
    Ok(())
}

async fn zone(root: &Path, settings: &Settings, client: &Client) -> Result<Zone> {
    let path = root.join("zone.json");
    if path.try_exists()? {
        let zone: Zone = serde_json::from_slice(&files::read(&path, 1024, true)?)?;
        ensure!(
            openwaf_cloudflare::valid_id(&zone.id)
                && crate::dns_name(&zone.name)
                && (settings.hostname == zone.name
                    || settings.hostname.ends_with(&format!(".{}", zone.name))),
            "invalid saved admin zone"
        );
        validate_zone(settings, &zone)?;
        return Ok(zone);
    }
    let labels: Vec<_> = settings.hostname.split('.').collect();
    for index in 0..labels.len() - 1 {
        let name = labels[index..].join(".");
        let value = api(
            client,
            Method::GET,
            "/zones",
            &[("name", name.clone()), ("per_page", "50".into())],
            None,
        )
        .await?;
        let rows = value["result"]
            .as_array()
            .context("invalid zone response")?;
        ensure!(rows.len() <= 1, "ambiguous admin zone");
        if let Some(row) = rows.first() {
            let id = row["id"]
                .as_str()
                .filter(|id| openwaf_cloudflare::valid_id(id))
                .context("invalid zone ID")?;
            ensure!(row["name"] == name, "unexpected admin zone");
            let zone = Zone {
                id: id.into(),
                name,
            };
            validate_zone(settings, &zone)?;
            files::write_new(&path, &serde_json::to_vec(&zone)?)?;
            files::sync_dir(root)?;
            return Ok(zone);
        }
    }
    anyhow::bail!("Cloudflare zone not found for admin hostname")
}

async fn records(client: &Client, zone: &Zone, name: &str) -> Result<Vec<Value>> {
    let value = api(
        client,
        Method::GET,
        &format!("/zones/{}/dns_records", zone.id),
        &[("name", name.into()), ("per_page", "50".into())],
        None,
    )
    .await?;
    let rows = value["result"]
        .as_array()
        .filter(|rows| rows.len() <= 50)
        .context("admin DNS response exceeds limit")?;
    ensure!(
        value["result_info"]["total_pages"]
            .as_u64()
            .is_some_and(|pages| pages <= 1)
            && rows.iter().all(|row| row["name"] == name),
        "admin DNS response ambiguous"
    );
    Ok(rows.clone())
}

fn config(
    root: &Path,
    settings: &Settings,
    zone: &Zone,
    staging: bool,
) -> Result<(crate::Config, Vec<u8>, PathBuf)> {
    let name = if staging { "staging" } else { "production" };
    let state = root.join(name);
    files::directory(&state)?;
    let manifest = if staging {
        root.join("staging-tls/manifest.json")
    } else {
        settings.tls_manifest.clone()
    };
    let bytes = serde_json::to_vec(&json!({
        "directory_url":if staging {"https://acme-staging-v02.api.letsencrypt.org/directory"} else {"https://acme-v02.api.letsencrypt.org/directory"},
        "hostname":zone.name, "additional_dns_names":[format!("*.{}",zone.name)],
        "retire_hostname":if settings.hostname != zone.name {Some(&settings.hostname)} else {None}, "state_dir":state, "master_key_file":master_key(),
        "tls_manifest":manifest,"terms_of_service_agreed":true,"deadline_seconds":180,
        "cloudflare":{"zone_id":zone.id,"zone_name":zone.name,"token_file":root.join("providers/cloudflare.enc"),"propagation_seconds":90}
    }))?;
    let path = root.join(format!("{name}-v2.json"));
    if path.try_exists()? {
        ensure!(
            files::read(&path, 65536, true)? == bytes,
            "admin ACME configuration changed; explicit migration required"
        );
    } else {
        files::write_new(&path, &bytes)?;
        files::sync_dir(root)?;
    }
    let mut config: crate::Config = serde_json::from_slice(&bytes)?;
    config.validate(false)?;
    Ok((config, bytes, path))
}
async fn child(path: &Path, mode: &str, cancel: &mut watch::Receiver<bool>) -> Result<()> {
    if *cancel.borrow() {
        return Ok(());
    }
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg(mode)
        .arg(path)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("start admin ACME child")?;
    let deadline = async {
        if mode == "watch" {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(Duration::from_secs(210)).await;
    };
    tokio::pin!(deadline);
    tokio::select! {
        result=child.wait()=>{
            let status = result.context("wait for admin ACME child")?;
            ensure!(status.success(), "admin ACME child failed ({mode}, {status}); see preceding ACME log");
            Ok(())
        },
        _=&mut deadline=>{stop_child(&mut child).await?;anyhow::bail!("admin ACME child deadline")},
        _=cancel.changed()=>{
            stop_child(&mut child).await?;
            Ok(())
        },
    }
}
async fn stop_child(child: &mut tokio::process::Child) -> Result<()> {
    if let Some(id) = child.id() {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(id)?);
        if nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).is_err() {
            eprintln!("Admin ACME child already stopped");
        }
    }
    match tokio::time::timeout(Duration::from_secs(25), child.wait()).await {
        Ok(result) => {
            result.context("wait for admin ACME child cleanup")?;
        }
        Err(_) => {
            child
                .kill()
                .await
                .context("force stop overdue admin ACME child")?;
            child
                .wait()
                .await
                .context("reap overdue admin ACME child")?;
        }
    }
    Ok(())
}

fn handoff_root() -> Result<PathBuf> {
    let root = PathBuf::from(
        std::env::var_os("OPENWAF_BOOTSTRAP_PROVIDER_ROOT")
            .context("bootstrap provider handoff is required")?,
    );
    ensure!(
        root.is_absolute(),
        "absolute bootstrap provider handoff required"
    );
    files::directory(&root)?;
    Ok(root)
}
async fn handoff(
    root: &Path,
    settings: &Settings,
    zone: &Zone,
    cancel: &mut watch::Receiver<bool>,
) -> Result<()> {
    let handoff = handoff_root()?;
    let descriptor = json!({"schema_version":2,"hostname":settings.hostname,"zone_id":zone.id,"zone_name":zone.name});
    let ready = handoff.join("zone.json");
    if ready.try_exists()? {
        ensure!(
            serde_json::from_slice::<Value>(&files::read(&ready, 4096, true)?)? == descriptor,
            "bootstrap provider zone changed"
        );
    } else {
        // Reject externally owned apex/wildcard before DNS is touched. An old
        // exact admin certificate is retired only with its durable owner marker.
        if settings.tls_manifest.try_exists()? {
            let manifest: Value =
                serde_json::from_slice(&files::read(&settings.tls_manifest, 65536, true)?)?;
            for entry in manifest["certificates"]
                .as_array()
                .context("invalid TLS manifest")?
            {
                let name = entry["hostname"].as_str().context("invalid TLS hostname")?;
                let reserved = name == zone.name || name == format!("*.{}", zone.name);
                ensure!(
                    !reserved
                        || (name == settings.hostname && root.join("admin-owned").try_exists()?),
                    "bootstrap apex/wildcard certificate has another owner"
                );
            }
        }
        files::write_new(&ready, &serde_json::to_vec(&descriptor)?)?;
        files::sync_dir(&handoff)?;
    }
    let wait = async {
        loop {
            let approval = handoff.join("reserved.json");
            if approval.try_exists()? {
                ensure!(
                    serde_json::from_slice::<Value>(&files::read(&approval, 4096, true)?)?
                        == descriptor,
                    "bootstrap reservation mismatch"
                );
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(120),wait)=>result.context("bootstrap provider reservation deadline")?,
        _=cancel.changed()=>anyhow::bail!("bootstrap reservation cancelled"),
    }
}

async fn work(
    root: &Path,
    settings: &Settings,
    status: &AtomicU8,
    mut cancel: watch::Receiver<bool>,
) -> Result<()> {
    let owned = root.join("admin-owned");
    if !owned.try_exists()? {
        if valid(settings) {
            status.store(4, Ordering::Relaxed); // Existing certificate keeps its external owner.
            let _ = cancel.changed().await;
            return Ok(());
        }
        ensure!(
            !contains_hostname(settings)?,
            "existing admin certificate has an external owner; do not replace it"
        );
        files::write_new(&owned, settings.hostname.as_bytes())?;
        files::sync_dir(root)?;
    }
    ensure!(
        files::read(&owned, 253, true)? == settings.hostname.as_bytes(),
        "admin certificate ownership mismatch"
    );
    for attempt in 0..5 {
        if *cancel.borrow() {
            return Ok(());
        }
        let result = async {
            status.store(5, Ordering::Relaxed);
            let client = Client::new(&credentials(root)?)?;
            status.store(6, Ordering::Relaxed);
            let zone = tokio::select! { biased;
                _=cancel.changed()=>return Ok(None),
                result=async {
                    let zone=zone(root,settings,&client).await?;
                    Ok::<_,anyhow::Error>(zone)
                }=>result?,
            };
            status.store(5, Ordering::Relaxed);
            handoff(root, settings, &zone, &mut cancel).await?;
            status.store(6, Ordering::Relaxed);
            provision_dns::run(root, settings, &client, &zone).await?;
            let (_, _, staging) = config(root, settings, &zone, true)?;
            if !root.join("staging-v2-verified").try_exists()? {
                status.store(7, Ordering::Relaxed);
                child(&staging, "renew-once", &mut cancel)
                    .await
                    .context("admin staging ACME issuance")?;
                if *cancel.borrow() {
                    return Ok(None);
                }
                files::write_new(&root.join("staging-v2-verified"), b"verified")?;
                files::sync_dir(root)?;
            }
            let (_, _, path) = config(root, settings, &zone, false)?;
            status.store(8, Ordering::Relaxed);
            child(&path, "renew-once", &mut cancel)
                .await
                .context("admin production ACME issuance")?;
            if *cancel.borrow() {
                return Ok(None);
            }
            ensure!(
                bundle_valid(root, settings)?,
                "apex/wildcard certificate not loaded after issuance"
            );
            Ok::<_, anyhow::Error>(Some(path))
        }
        .await;
        match result {
            Ok(Some(path)) => {
                status.store(1, Ordering::Relaxed);
                return child(&path, "watch", &mut cancel)
                    .await
                    .context("admin production ACME renewal");
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                if *cancel.borrow() {
                    return Ok(());
                }
                let code = match status.load(Ordering::Relaxed) {
                    5 => "bootstrap_provider_failed",
                    6 => "bootstrap_dns_failed",
                    7 => "bootstrap_staging_failed",
                    _ => "bootstrap_production_failed",
                };
                files::replace_secret(
                    &root.join("last-error.json"),
                    &serde_json::to_vec(&json!({"reason":code}))?,
                )?;
                status.store(2, Ordering::Relaxed);
                eprintln!("Admin bootstrap degraded: {error:#}");
            }
        }
        tokio::select! {_=cancel.changed()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(30*(1<<attempt)))=>{}}
    }
    anyhow::bail!("admin bootstrap retry budget exhausted; current certificate and state retained")
}
fn heartbeat(root: &Path, settings: &Settings, state: u8) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let renewal_path = root.join("production/health.json");
    let renewal_state = if state != 1 {
        "pending"
    } else if renewal_path.try_exists()? {
        let health: Value = serde_json::from_slice(&files::read(&renewal_path, 4096, true)?)?;
        if health["observed_at_unix_ms"]
            .as_u64()
            .is_none_or(|time| time > now || now - time > 30_000)
        {
            "unavailable"
        } else {
            match health["state"].as_str() {
                Some("healthy") => "current",
                Some("renewing") => "renewing",
                Some("starting") => "starting",
                Some("degraded") => "degraded",
                _ => "unavailable",
            }
        }
    } else {
        "starting"
    };
    let renewal_failed = ["degraded", "unavailable"].contains(&renewal_state);
    let effective_state = if state == 1 && renewal_failed {
        2
    } else {
        state
    };
    let reason = if state == 1 && renewal_failed {
        Some("bootstrap_production_failed".to_owned())
    } else if state == 1 {
        None
    } else if root.join("last-error.json").try_exists()? {
        serde_json::from_slice::<Value>(&files::read(&root.join("last-error.json"),1024,true)?)?["reason"].as_str().map(str::to_owned)
    } else {
        None
    };
    let observation = json!({
        "reason":reason,"renewal_state":renewal_state,
        "schema_version":2,"hostname":settings.hostname,"observed_at_unix_ms":now,"ready":valid(settings),
        "state":match effective_state {1=>"current",2=>"degraded",3=>"exhausted",4=>"external",5=>"reserving",6=>"configuring_dns",7=>"staging",8=>"production",_=>"starting"},
        "dns_state":if root.join("dns-v2-complete.json").try_exists()? {"complete"} else {"pending"},
        "tls_state":if root.join("production-v2.json").try_exists()? && bundle_valid(root,settings)? {"current"} else {"pending"},
        "provider_state":if std::env::var_os("OPENWAF_BOOTSTRAP_PROVIDER_ROOT").map(PathBuf::from).is_some_and(|path| path.join("reserved.json").is_file()) {"reserved"} else {"pending"},
    });
    let bytes = serde_json::to_vec(&observation)?;
    files::replace_secret(&root.join("health.json"), &bytes)?;
    if std::env::var_os("OPENWAF_BOOTSTRAP_PROVIDER_ROOT").is_some() {
        files::replace_secret(&handoff_root()?.join("health.json"), &bytes)?;
    }
    Ok(())
}
pub fn health() -> Result<()> {
    let root = root();
    let settings = settings(&root)?;
    let value: Value =
        serde_json::from_slice(&files::read(&root.join("health.json"), 4096, true)?)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    ensure!(
        value["ready"] == true
            && value["hostname"] == settings.hostname
            && value["observed_at_unix_ms"]
                .as_u64()
                .is_some_and(|observed| observed <= now && now - observed <= 30000)
            && valid(&settings),
        "admin TLS bootstrap not ready"
    );
    Ok(())
}
pub async fn start() -> Result<()> {
    let root = root();
    files::directory(&root)?;
    let settings = settings(&root)?;
    let _lock = files::Lock::acquire(root.join(".admin-owner.lock"))?;
    let status = Arc::new(AtomicU8::new(0));
    let (send, receive) = watch::channel(false);
    let work = work(&root, &settings, &status, receive);
    tokio::pin!(work);
    let shutdown = crate::interrupted();
    tokio::pin!(shutdown);
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    let mut finished = false;
    loop {
        tokio::select! {biased;
            result=&mut shutdown=>{
                send.send_replace(true);
                if !finished {tokio::time::timeout(Duration::from_secs(30),&mut work).await.context("admin ACME shutdown deadline")??;}
                return result
            },
            result=&mut work,if !finished=>{
                finished=true;
                if status.load(Ordering::Relaxed)==1 { files::replace_secret(&root.join("last-error.json"), &serde_json::to_vec(&json!({"reason":"bootstrap_production_failed"}))?)?; }
                status.store(3,Ordering::Relaxed);
                if let Err(error)=result {eprintln!("Admin certificate owner exhausted/degraded: {error:#}");}
            },
            _=timer.tick()=>if let Err(error)=heartbeat(&root,&settings,status.load(Ordering::Relaxed)) {
                send.send_replace(true);
                if !finished {tokio::time::timeout(Duration::from_secs(30),&mut work).await.context("admin ACME shutdown deadline")??;}
                return Err(error).context("admin ACME heartbeat failed")
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings {
            hostname: "admin.example.com".into(),
            ipv4: Some("192.0.2.10".parse().expect("fixture IP")),
            ipv6: None,
            proxied: true,
            tls_manifest: "/not-used".into(),
        }
    }
    #[test]
    fn accepts_only_zone_or_direct_child() -> Result<()> {
        let zone = Zone {
            id: "a".repeat(32),
            name: "example.com".into(),
        };
        let mut settings = settings();
        validate_zone(&settings, &zone)?;
        settings.hostname = "example.com".into();
        validate_zone(&settings, &zone)?;
        for name in ["admin.ops.example.com", "otherexample.com", "other.net"] {
            settings.hostname = name.into();
            assert!(validate_zone(&settings, &zone).is_err());
        }
        Ok(())
    }
    #[cfg(feature = "integration-test-provider")]
    #[tokio::test]
    #[ignore = "requires local HTTPS Cloudflare simulation"]
    async fn cloudflare_bundle_dns_reconciliation() -> Result<()> {
        let mut secret = [0; 24];
        openssl::rand::rand_bytes(&mut secret)?;
        let client = Client::new(&openwaf_cloudflare::Credentials {
            auth_type: "api_token".into(),
            secret: secret.iter().map(|byte| format!("{byte:02x}")).collect(),
            email: None,
        })?;
        let zone = Zone {
            id: "a".repeat(32),
            name: "example.com".into(),
        };
        for mode in [
            "v2-ok",
            "v2-replace",
            "v2-unknown-committed",
            "v2-unknown-uncommitted",
            "v2-unknown-delete",
            "v2-unknown-patch",
            "v2-denied",
            "v2-unrelated",
            "v2-delegated",
            "v2-read-denied",
            "v2-incomplete",
        ] {
            api(
                &client,
                Method::GET,
                &format!("/__control/{mode}"),
                &[],
                None,
            )
            .await?;
            let root = tempfile::tempdir()?;
            let settings = settings();
            let first = provision_dns::run(root.path(), &settings, &client, &zone).await;
            let unknown = mode.starts_with("v2-unknown");
            let success = ["v2-ok", "v2-replace"].contains(&mode);
            if success {
                first?;
            } else {
                assert!(first.is_err(), "{mode}");
            }
            if unknown {
                assert!(root.path().join("dns-pending.json").exists(), "{mode}");
                let before = api(&client, Method::GET, "/__stats", &[], None).await?;
                let retry = provision_dns::run(root.path(), &settings, &client, &zone).await;
                if mode == "v2-unknown-uncommitted" {
                    assert!(retry.is_err());
                    let after = api(&client, Method::GET, "/__stats", &[], None).await?;
                    assert_eq!(after["result"]["writes"], before["result"]["writes"]);
                    continue;
                }
                retry?;
            }
            let stats = api(&client, Method::GET, "/__stats", &[], None).await?;
            if success || unknown {
                let rows = stats["result"]["rows"].as_array().context("rows")?;
                assert!(rows.iter().any(|row| row["name"] == "example.com"
                    && row["type"] == "A"
                    && row["content"] == "192.0.2.10"));
                for name in ["*.example.com", "admin.example.com"] {
                    assert!(rows.iter().any(|row| row["name"] == name
                        && row["type"] == "CNAME"
                        && row["content"] == "example.com"));
                }
                assert!(
                    !rows
                        .iter()
                        .any(|row| row["name"] == "example.com" && row["type"] == "AAAA")
                );
                if mode == "v2-replace" {
                    assert!(rows.iter().any(|row| row["type"] == "MX"));
                    assert!(rows.iter().any(|row| row["content"] == "keep-me"));
                    assert!(rows.iter().any(|row| row["name"] == "mail.example.com"));
                }
                api(&client, Method::GET, "/__mutate", &[], None).await?;
                provision_dns::run(root.path(), &settings, &client, &zone).await?;
                let after = api(&client, Method::GET, "/__stats", &[], None).await?;
                assert_eq!(
                    after["result"]["writes"], stats["result"]["writes"],
                    "restart must not overwrite manual DNS"
                );
            } else if mode != "v2-denied" {
                assert_eq!(stats["result"]["writes"], 0, "{mode}");
            }
        }
        // IPv6-only, dual-stack and an admin at the zone apex use the same flow.
        for dual in [false, true] {
            api(&client, Method::GET, "/__control/v2-ok", &[], None).await?;
            let root = tempfile::tempdir()?;
            let mut settings = settings();
            settings.hostname = zone.name.clone();
            settings.ipv6 = Some("2001:db8::10".parse()?);
            if !dual {
                settings.ipv4 = None;
            }
            provision_dns::run(root.path(), &settings, &client, &zone).await?;
            let stats = api(&client, Method::GET, "/__stats", &[], None).await?;
            let rows = stats["result"]["rows"].as_array().context("fixture rows")?;
            assert!(rows.iter().any(|row| row["name"] == zone.name
                && row["type"] == "AAAA"
                && row["content"] == "2001:db8::10"));
            assert_eq!(rows.iter().any(|row| row["type"] == "A"), dual);
            assert!(!rows.iter().any(|row| row["name"] == "admin.example.com"));
            provision_dns::run(root.path(), &settings, &client, &zone).await?;
        }
        // Nested admin input is rejected without any DNS write.
        api(&client, Method::GET, "/__control/v2-ok", &[], None).await?;
        let mut settings = settings();
        settings.hostname = "admin.ops.example.com".into();
        let root = tempfile::tempdir()?;
        assert!(
            provision_dns::run(root.path(), &settings, &client, &zone)
                .await
                .is_err()
        );
        assert_eq!(
            api(&client, Method::GET, "/__stats", &[], None).await?["result"]["writes"],
            0
        );
        Ok(())
    }
    #[cfg(feature = "integration-test-provider")]
    #[tokio::test]
    #[ignore = "requires local HTTPS Cloudflare simulation"]
    async fn cloudflare_two_txt_leases_survive_restart_and_cleanup() -> Result<()> {
        let root = tempfile::tempdir()?;
        let key = root.path().join("key");
        let state = root.path().join("state");
        files::directory(&state)?;
        let mut random = [0; 32];
        openssl::rand::rand_bytes(&mut random)?;
        files::write_new(&key, &random)?;
        let credentials = openwaf_cloudflare::Credentials {
            auth_type: "api_token".into(),
            secret: random.iter().map(|byte| format!("{byte:02x}")).collect(),
            email: None,
        };
        let token = root.path().join("token");
        files::write_new(&token, &openwaf_cloudflare::seal(&credentials, &random)?)?;
        let client = Client::new(&credentials)?;
        api(&client, Method::GET, "/__control/v2-ok", &[], None).await?;
        let config: crate::dns::Config = serde_json::from_value(
            json!({"zone_id":"a".repeat(32),"zone_name":"example.com","token_file":token,"test_api":{"base_url":std::env::var("OPENWAF_TEST_CLOUDFLARE_API")?,"ca_pem":std::env::var("OPENWAF_TEST_CLOUDFLARE_CA")?}}),
        )?;
        api(&client,Method::POST,&format!("/zones/{}/dns_records","a".repeat(32)),&[],Some(&json!({"type":"TXT","name":"_acme-challenge.example.com","content":"keep-me","comment":"external"}))).await?;
        let mut dns = crate::dns::Cloudflare::open(&config, &state, &key)?;
        dns.present("example.com", &"a".repeat(43)).await?;
        dns.present("*.example.com", &"b".repeat(43)).await?;
        assert!(dns.present("*.example.com", &"c".repeat(43)).await.is_err());
        drop(dns);
        let mut dns = crate::dns::Cloudflare::open(&config, &state, &key)?;
        dns.cleanup().await?;
        assert!(!state.join("dns-lease.enc").exists());
        let stats = api(&client, Method::GET, "/__stats", &[], None).await?;
        assert_eq!(stats["result"]["records"], 1);
        assert_eq!(stats["result"]["rows"][0]["content"], "keep-me");
        Ok(())
    }
}
