//! Bounded certificate queue. Reuses the ACME worker; provider secrets stay in local files.
use super::*;
use std::path::{Path, PathBuf};

pub(super) fn configured() -> bool {
    std::env::var_os("OPENWAF_APPLICATIONS_ACME_TEMPLATE").is_some()
}
struct Provider {
    template: serde_json::Value,
    root: PathBuf,
    binary: PathBuf,
}
impl Provider {
    fn load() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os("OPENWAF_APPLICATIONS_ACME_TEMPLATE") else {
            return Ok(None);
        };
        let bytes = crypto::private_file(Path::new(&path), 65536)?;
        let template: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid applications ACME template")?;
        ensure!(
            template.is_object()
                && template.get("cloudflare").is_some()
                && template.get("challenge_listen").is_none()
                && template["terms_of_service_agreed"] == true,
            "applications auto TLS requires a DNS-01 ACME template with accepted terms"
        );
        let root: PathBuf = std::env::var_os("OPENWAF_APPLICATIONS_ACME_ROOT")
            .context("applications ACME root required")?
            .into();
        ensure!(
            root.is_absolute(),
            "applications ACME root must be absolute"
        );
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        let root = root.canonicalize()?;
        let binary = std::env::var_os("OPENWAF_APPLICATIONS_ACME_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/local/bin/openwaf-acme"));
        ensure!(binary.is_absolute(), "ACME binary must be absolute");
        Ok(Some(Self {
            template,
            root,
            binary,
        }))
    }
    fn state(&self, hostname: &str) -> PathBuf {
        let key = openssl::sha::sha256(hostname.as_bytes())
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        self.root.join(key)
    }
    fn input(&self, hostname: &str) -> Result<PathBuf> {
        // The hostname is validated independently before it is used as config data.
        let base = hostname.strip_prefix("*.").unwrap_or(hostname);
        ensure!(
            openwaf_config::hostname(base)? == base,
            "invalid certificate hostname"
        );
        let state = self.state(hostname);
        if !state.try_exists()? {
            ensure!(
                std::fs::read_dir(&self.root)?.take(129).count() < 128,
                "ACME host-state capacity reached"
            );
        }
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        let mut config = self.template.clone();
        config["hostname"] = hostname.into();
        config["state_dir"] = state.to_string_lossy().as_ref().into();
        let bytes = serde_json::to_vec(&config)?;
        let path = state.join("application.json");
        if path.try_exists()? {
            ensure!(
                crypto::private_file(&path, 65536)?.as_slice() == bytes.as_slice(),
                "ACME template changed; inspect state and replace generated config explicitly"
            );
        } else {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::File::open(state)?.sync_all()?;
        }
        Ok(path)
    }
}

fn wildcard_coverage(app: &App, provider: &Provider, hostname: &str) -> Result<Option<String>> {
    let Some(store) = &app.application_tls else {
        return Ok(None);
    };
    let certificate = if hostname.starts_with("*.") {
        // An existing generated config means this queue may own its renewal.
        // Never skip that renewal merely because its own wildcard is still valid.
        if provider
            .state(hostname)
            .join("application.json")
            .try_exists()?
        {
            return Ok(None);
        }
        store.certificate(hostname)
    } else {
        store.certificate_for(hostname)
    };
    Ok(certificate
        .filter(|c| c.hostname.starts_with("*."))
        .map(|c| c.hostname))
}

async fn reconcile_coverage(app: &App, provider: &Provider, hostname: &str) -> Result<bool> {
    let coverage = wildcard_coverage(app, provider, hostname)?;
    if let Some(covering) = &coverage {
        sqlx::query("UPDATE application_certificates SET state='covered',covered_by_hostname=$2,attempts=0,updated_at=now() WHERE hostname=$1 AND (state<>'covered' OR covered_by_hostname IS DISTINCT FROM $2)")
            .bind(hostname).bind(covering).execute(&app.db).await?;
    } else {
        sqlx::query("UPDATE application_certificates SET state='pending',covered_by_hostname=NULL,attempts=0,next_attempt=now(),updated_at=now() WHERE hostname=$1 AND state='covered'")
            .bind(hostname).execute(&app.db).await?;
    }
    Ok(coverage.is_some())
}
fn health(app: &App, state: &str, reason: Option<&str>) {
    *app.application_certificate_health
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        serde_json::json!({"state":state,"reason":reason,"observed_at_unix_ms":now_ms()});
}
pub async fn run(app: &App, mut stopped: tokio::sync::watch::Receiver<bool>) {
    let provider = if app.applications.is_some() && configured() {
        match Provider::load() {
            Ok(Some(provider)) => Some(provider),
            _ => {
                health(
                    app,
                    "degraded",
                    Some(
                        "Check the private ACME provider template and state directory permissions on the server",
                    ),
                );
                None
            }
        }
    } else {
        health(app, "disabled", None);
        None
    };
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _=tick.tick()=>{}, _=app.certificates.wake.notified()=>{}, _=stopped.changed()=>return };
        if crate::certificates::cycle(app, &mut stopped).await.is_err() {
            eprintln!("Certificates worker cycle outcome=degraded reason=queue");
        }
        if *stopped.borrow() {
            return;
        }
        let Some(provider) = &provider else {
            continue;
        };
        if cycle(app, provider, &mut stopped).await.is_err() {
            health(
                app,
                "degraded",
                Some(
                    "Certificate queue or worker failed; inspect provider configuration and job status before retrying",
                ),
            );
            eprintln!("Applications certificate worker outcome=degraded reason=queue_or_child");
        } else {
            health(app, "available", None);
        }
        if *stopped.borrow() {
            return;
        }
    }
}
async fn cycle(
    app: &App,
    provider: &Provider,
    stopped: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut domains: Vec<String> =
        sqlx::query_scalar("SELECT domain FROM applications ORDER BY id LIMIT 65")
            .fetch_all(&app.db)
            .await?;
    let base: Option<String> = sqlx::query_scalar(
        "SELECT preview_base_domain FROM application_settings WHERE singleton=true",
    )
    .fetch_one(&app.db)
    .await?;
    if let Some(base) = base {
        domains.push(format!("*.{base}"));
    }
    ensure!(domains.len() <= 65, "certificate inventory limit");
    let explicit: Vec<String> =
        sqlx::query_scalar("SELECT hostname FROM certificate_requests LIMIT 129")
            .fetch_all(&app.db)
            .await?;
    let reserved: Vec<String> =
        sqlx::query_scalar("SELECT hostname FROM bootstrap_certificate_ownership LIMIT 4")
            .fetch_all(&app.db)
            .await?;
    ensure!(reserved.len() <= 3, "bootstrap ownership limit");
    domains.retain(|hostname| !explicit.contains(hostname) && !reserved.contains(hostname));
    sqlx::query("DELETE FROM application_certificates WHERE NOT (hostname=ANY($1))")
        .bind(&domains)
        .execute(&app.db)
        .await?;
    for hostname in &domains {
        sqlx::query("INSERT INTO application_certificates(hostname) VALUES($1) ON CONFLICT(hostname) DO NOTHING").bind(hostname).execute(&app.db).await?;
        reconcile_coverage(app, provider, hostname).await?;
    }
    let Some(row)=sqlx::query("SELECT hostname FROM application_certificates WHERE hostname=ANY($1) AND state<>'covered' AND attempts<5 AND next_attempt<=now() ORDER BY next_attempt LIMIT 1").bind(&domains).fetch_optional(&app.db).await? else {return Ok(());};
    let hostname: String = row.try_get("hostname")?;
    // Recheck after database awaits in case a wildcard was hot-reloaded meanwhile.
    if reconcile_coverage(app, provider, &hostname).await? {
        return Ok(());
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    let claimed = sqlx::query("UPDATE application_certificates SET state='running',attempts=attempts+1,next_attempt=now()+interval '10 minutes',updated_at=now() WHERE hostname=$1 AND attempts<5 AND state<>'covered' AND NOT EXISTS(SELECT 1 FROM certificate_requests WHERE hostname=$1)").bind(&hostname).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    if claimed == 0 {
        return Ok(());
    }
    ensure!(claimed == 1, "certificate job conflict");
    let result = async {
        let input = provider.input(&hostname)?;
        crate::certificates::run_worker(&provider.binary, &input, stopped).await
    }
    .await;
    let successful = result.is_ok();
    ensure!(sqlx::query("UPDATE application_certificates SET state=$2,attempts=CASE WHEN $3 THEN 0 ELSE attempts END,next_attempt=CASE WHEN $3 THEN now()+interval '12 hours' ELSE now()+interval '5 minutes' END,updated_at=now() WHERE hostname=$1").bind(&hostname).bind(if successful{"current"}else{"degraded"}).bind(successful).execute(&app.db).await?.rows_affected()==1,"certificate job acknowledgement missing");
    result
}
