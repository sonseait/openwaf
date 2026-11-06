use super::*;
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    process::Stdio,
};
use tokio::process::Command;

impl Provider {
    fn prepare_credentials(&self, root: &FsPath, key: &MasterKey) -> Result<()> {
        let Some(encrypted) = &self.credential else {
            return Ok(());
        };
        let plain = key.open(&providers::secret_name(&self.id), encrypted)?;
        let credentials: openwaf_cloudflare::Credentials = serde_json::from_slice(&plain)?;
        let master = crypto::private_file(
            FsPath::new(
                self.template["master_key_file"]
                    .as_str()
                    .context("master key path required")?,
            ),
            32,
        )?;
        let sealed = openwaf_cloudflare::seal(&credentials, &master)?;
        for directory in [root.join("providers"), root.join("staging")] {
            if !directory.try_exists()? {
                std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
            }
            let m = std::fs::symlink_metadata(&directory)?;
            ensure!(
                m.is_dir() && m.permissions().mode() & 0o077 == 0,
                "private provider state required"
            );
        }
        let parent = root.join("providers");
        let temp = parent.join(format!(".{}", crypto::random_token()?));
        let path = parent.join(format!("{}.enc", self.id));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let result = (|| -> Result<()> {
            file.write_all(&sealed)?;
            file.sync_all()?;
            std::fs::rename(&temp, &path)?;
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() && temp.try_exists()? {
            std::fs::remove_file(&temp).context("provider temporary cleanup failed")?;
        }
        result
    }
    fn state(&self, root: &FsPath, hostname: &str) -> PathBuf {
        root.join(crypto::hex(&sha256(
            format!("{}:{hostname}", self.id).as_bytes(),
        )))
    }
    fn input(&self, root: &FsPath, hostname: &str) -> Result<PathBuf> {
        let state = self.state(root, hostname);
        if !state.try_exists()? {
            ensure!(
                std::fs::read_dir(root)?.take(257).count() < 256,
                "certificate state capacity"
            );
            std::fs::DirBuilder::new().mode(0o700).create(&state)?;
        }
        let meta = std::fs::symlink_metadata(&state)?;
        ensure!(
            meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
            "private certificate state required"
        );
        let mut template = self.template.clone();
        template["hostname"] = hostname.into();
        template["state_dir"] = state.to_string_lossy().as_ref().into();
        let bytes = serde_json::to_vec(&template)?;
        let path = state.join("request.json");
        if path.try_exists()? {
            ensure!(
                crypto::private_file(&path, 65536)?.as_slice() == bytes,
                "immutable certificate input changed"
            );
        } else {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::File::open(&state)?.sync_all()?;
        }
        // Migrated jobs retain their original immutable input/fingerprint and account
        // directory. The child receives a derived input using the DB credential
        // bridge; the original read-only token/template files are no longer read.
        let bridge = root.join("providers").join(format!("{}.enc", self.id));
        if self.credential.is_some()
            && template["cloudflare"]["token_file"] != bridge.to_string_lossy().as_ref()
        {
            template["cloudflare"]["token_file"] = bridge.to_string_lossy().as_ref().into();
            let managed = state.join("managed-request.json");
            let bytes = serde_json::to_vec(&template)?;
            if managed.try_exists()? {
                ensure!(
                    crypto::private_file(&managed, 65536)?.as_slice() == bytes,
                    "immutable managed input changed"
                );
            } else {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&managed)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                std::fs::File::open(&state)?.sync_all()?;
            }
            return Ok(managed);
        }
        Ok(path)
    }
}

struct DiagnosticTask(tokio::task::JoinHandle<std::io::Result<()>>);

impl Drop for DiagnosticTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl DiagnosticTask {
    async fn finish(mut self) -> Result<()> {
        match tokio::time::timeout(Duration::from_secs(2), &mut self.0).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(_))) => anyhow::bail!("certificate diagnostics read failed"),
            Ok(Err(_)) => anyhow::bail!("certificate diagnostics task failed"),
            Err(_) => {
                self.0.abort();
                let _ = (&mut self.0).await;
                anyhow::bail!("certificate diagnostics drain timed out")
            }
        }
    }
}

fn parse_diagnostic(line: &str) -> Option<(&'static str, &'static str)> {
    let mut f = line.split_ascii_whitespace();
    if f.next()? != "OWAF_STAGE" {
        return None;
    }
    let stage = match f.next()? {
        "input" => "input",
        "account" => "account",
        "order" => "order",
        "dns_present" => "dns_present",
        "dns_propagation" => "dns_propagation",
        "ca_validation" => "ca_validation",
        "finalize" => "finalize",
        "certificate" => "certificate",
        "dns_cleanup" => "dns_cleanup",
        "publish" => "publish",
        _ => return None,
    };
    let status = match f.next()? {
        "started" => "started",
        "ok" => "ok",
        "failed" => "failed",
        _ => return None,
    };
    if f.next().is_some() {
        return None;
    }
    Some((stage, status))
}

fn parse_dns_diagnostic(line: &str) -> Option<&'static str> {
    let mut fields = line.split_ascii_whitespace();
    if fields.next()? != "OWAF_DNS" {
        return None;
    }
    let reason = match fields.next()? {
        "nxdomain" => "nxdomain",
        "servfail" => "servfail",
        "no_records" => "no_records",
        "timeout" => "timeout",
        "network" => "network",
        "protocol" => "protocol",
        "txt_mismatch" => "txt_mismatch",
        _ => return None,
    };
    fields.next().is_none().then_some(reason)
}

fn health(app: &App, state: &str) {
    *app.certificates
        .health
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        serde_json::json!({"state":state,"observed_at_unix_ms":openwaf_telemetry::now_ms()});
}

pub(super) async fn cycle(
    app: &App,
    stopped: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let Ok(_gate) = app.certificates.mutation.try_lock() else {
        return Ok(());
    };
    if base_settings(app).is_err() {
        health(app, "disabled");
        return Ok(());
    }
    let settings = match settings(app).await {
        Ok(settings) => settings,
        Err(_) => {
            health(app, "degraded");
            anyhow::bail!("certificate providers unavailable");
        }
    };
    health(app, "available");
    let result = process(app, &settings, stopped).await;
    if result.is_err() {
        health(app, "degraded");
    }
    result
}
async fn process(
    app: &App,
    settings: &Settings,
    stopped: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let rows=sqlx::query("SELECT hostname,provider_id,provider_fingerprint FROM certificate_requests ORDER BY hostname LIMIT 129").fetch_all(&app.db).await?;
    ensure!(rows.len() <= 128, "certificate request capacity");
    for row in rows {
        let hostname: String = row.try_get("hostname")?;
        let id: String = row.try_get("provider_id")?;
        let fingerprint: String = row.try_get("provider_fingerprint")?;
        let Some(provider) = settings
            .providers
            .get(&id)
            .filter(|p| p.fingerprint == fingerprint)
        else {
            sqlx::query("UPDATE certificate_requests SET state='degraded',covered_by_hostname=NULL,last_error_code='provider_changed',attempts=5,updated_at=now() WHERE hostname=$1 AND last_error_code IS DISTINCT FROM 'provider_changed'").bind(&hostname).execute(&app.db).await?;
            continue;
        };
        reconcile(app, settings, provider, &hostname).await?;
    }
    let Some(row)=sqlx::query("SELECT hostname,provider_id FROM certificate_requests WHERE state<>'covered' AND attempts<5 AND next_attempt<=now() ORDER BY next_attempt,hostname LIMIT 1").fetch_optional(&app.db).await? else {return Ok(());};
    if *stopped.borrow() {
        return Ok(());
    }
    let hostname: String = row.try_get("hostname")?;
    let id: String = row.try_get("provider_id")?;
    ensure!(
        !crate::certificate_bootstrap::reserved(&app.db, &hostname).await?,
        "certificate reserved by bootstrap"
    );
    let provider = settings
        .providers
        .get(&id)
        .context("certificate provider missing")?;
    if reconcile(app, settings, provider, &hostname).await? {
        return Ok(());
    }
    ensure!(sqlx::query("UPDATE certificate_requests SET state='running',attempts=attempts+1,next_attempt=now()+interval '10 minutes',last_error_code=NULL,updated_at=now() WHERE hostname=$1 AND state<>'covered' AND attempts<5").bind(&hostname).execute(&app.db).await?.rows_affected()==1,"certificate job conflict");
    let provider = provider.clone();
    let root = settings.root.clone();
    let name = hostname.clone();
    let key = app.key.clone();
    let result = async {
        let input = tokio::task::spawn_blocking(move || {
            provider.prepare_credentials(&root, &key)?;
            provider.input(&root, &name)
        })
        .await
        .context("certificate input worker stopped")??;
        run_worker(&settings.binary, &input, stopped).await
    }
    .await;
    let successful = result.is_ok();
    let error = if successful {
        None
    } else if *stopped.borrow() {
        Some("interrupted")
    } else {
        Some("worker_failed")
    };
    ensure!(sqlx::query("UPDATE certificate_requests SET state=$2,attempts=CASE WHEN $3 THEN 0 ELSE attempts END,last_error_code=$4,next_attempt=CASE WHEN $3 THEN now()+interval '12 hours' ELSE now()+interval '5 minutes' END,updated_at=now() WHERE hostname=$1 AND state='running'").bind(&hostname).bind(if successful {"current"} else {"degraded"}).bind(successful).bind(error).execute(&app.db).await?.rows_affected()==1,"certificate acknowledgement missing");
    result
}
async fn reconcile(
    app: &App,
    settings: &Settings,
    provider: &Provider,
    hostname: &str,
) -> Result<bool> {
    let covered = if provider.environment == "production" {
        live(app, hostname)
            .filter(|c| c.hostname.starts_with("*."))
            .filter(|_| {
                !hostname.starts_with("*.")
                    || !provider
                        .state(&settings.root, hostname)
                        .join("request.json")
                        .exists()
            })
            .map(|c| c.hostname)
    } else {
        None
    };
    if let Some(covering) = &covered {
        sqlx::query("UPDATE certificate_requests SET state='covered',covered_by_hostname=$2,attempts=0,last_error_code=NULL,updated_at=now() WHERE hostname=$1 AND (state<>'covered' OR covered_by_hostname IS DISTINCT FROM $2)").bind(hostname).bind(covering).execute(&app.db).await?;
    } else {
        sqlx::query("UPDATE certificate_requests SET state='pending',covered_by_hostname=NULL,attempts=0,next_attempt=now(),updated_at=now() WHERE hostname=$1 AND state='covered'").bind(hostname).execute(&app.db).await?;
    }
    Ok(covered.is_some())
}

/// The certificate supervisor owns one child at a time, including Applications.
/// Child diagnostics remain private; API errors use finite, redacted codes.
pub(crate) async fn run_worker(
    binary: &FsPath,
    input: &FsPath,
    stopped: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    ensure!(!*stopped.borrow(), "certificate owner stopping");
    let mut child = Command::new(binary)
        .arg("renew-once")
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stderr = child
        .stderr
        .take()
        .context("certificate diagnostic pipe missing")?;
    let diagnostics = DiagnosticTask(tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut r = stderr;
        let mut b = [0u8; 512];
        let mut line = Vec::with_capacity(96);
        let mut over = false;
        let mut n = 0;
        loop {
            let len = r.read(&mut b).await?;
            if len == 0 {
                break;
            }
            for c in &b[..len] {
                if *c == b'\n' {
                    if !over
                        && n < 64
                        && let Ok(t) = std::str::from_utf8(&line)
                    {
                        if let Some((stage, status)) = parse_diagnostic(t) {
                            eprintln!("certificate diagnostic: stage={stage} status={status}");
                            n += 1;
                        } else if let Some(reason) = parse_dns_diagnostic(t) {
                            eprintln!("certificate DNS diagnostic: reason={reason}");
                            n += 1;
                        }
                    }
                    line.clear();
                    over = false;
                } else if line.len() < 128 {
                    line.push(*c);
                } else {
                    over = true;
                }
            }
        }
        Ok::<(), std::io::Error>(())
    }));
    let result = tokio::select! {
        result=child.wait()=>Some(result),
        _=tokio::time::sleep(Duration::from_secs(210))=>None,
        _=stopped.changed()=>None,
    };
    if let Some(status) = result {
        let status = status?;
        diagnostics.finish().await?;
        ensure!(status.success(), "certificate worker failed");
        return Ok(());
    }
    if let Some(pid) = child.id() {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .context("cannot stop certificate worker")?;
    }
    match tokio::time::timeout(Duration::from_secs(25), child.wait()).await {
        Ok(status) => {
            status?;
        }
        Err(_) => child.kill().await?,
    }
    diagnostics.finish().await?;
    anyhow::bail!("certificate worker cancelled or deadline exceeded")
}

#[cfg(test)]
mod diagnostic_tests {
    use super::{parse_diagnostic, parse_dns_diagnostic};

    #[test]
    fn dns_diagnostics_only_accept_finite_reasons_without_payloads() {
        for reason in [
            "nxdomain",
            "servfail",
            "no_records",
            "timeout",
            "network",
            "protocol",
            "txt_mismatch",
        ] {
            assert_eq!(
                parse_dns_diagnostic(&format!("OWAF_DNS {reason}")),
                Some(reason)
            );
        }
        for line in [
            "OWAF_DNS",
            "OWAF_DNS provider-secret",
            "OWAF_DNS timeout TXT=secret",
            "provider response: sensitive data",
            "OWAF_STAGE dns_propagation failed",
        ] {
            assert_eq!(parse_dns_diagnostic(line), None);
        }
    }

    #[test]
    fn diagnostics_reject_external_text_and_only_accept_finite_fields() {
        assert_eq!(
            parse_diagnostic("OWAF_STAGE ca_validation started"),
            Some(("ca_validation", "started"))
        );
        for line in [
            "provider response: sensitive data",
            "OWAF_STAGE dns_present ok extra=value",
            "OWAF_STAGE unknown ok",
            "OWAF_STAGE account arbitrary",
            "OWAF_STAGE",
        ] {
            assert_eq!(parse_diagnostic(line), None);
        }
    }
}
