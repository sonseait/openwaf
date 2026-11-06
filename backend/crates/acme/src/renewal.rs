//! Single-owner renewal supervisor. Child uses the same bounded issuance/cleanup
//! path as one-shot mode; never publish partial output or bypass TLS validation.
use crate::{Config, files};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub renew_before_seconds: u64,
    pub check_seconds: u64,
    pub retry_seconds: u64,
    pub max_retry_seconds: u64,
    pub max_failures: u8,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            renew_before_seconds: 30 * 86400,
            check_seconds: 60,
            retry_seconds: 30,
            max_retry_seconds: 3600,
            max_failures: 5,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=90 * 86400).contains(&self.renew_before_seconds)
                && (1..=3600).contains(&self.check_seconds)
                && (1..=3600).contains(&self.retry_seconds)
                && (self.retry_seconds..=86400).contains(&self.max_retry_seconds)
                && (1..=16).contains(&self.max_failures),
            "invalid renewal limits"
        );
        Ok(())
    }
    fn backoff(&self, failures: u8) -> Duration {
        Duration::from_secs(
            self.retry_seconds
                .saturating_mul(1u64 << failures.saturating_sub(1).min(16))
                .min(self.max_retry_seconds),
        )
    }
}
struct Input(PathBuf);
impl Drop for Input {
    fn drop(&mut self) {
        if std::fs::remove_file(&self.0).is_err() {
            eprintln!("ACME renewal input cleanup failed");
        }
    }
}
pub async fn watch(config: Config, bytes: &[u8]) -> Result<()> {
    let lock = files::Lock::acquire(config.state_dir.join(".scheduler.lock"))?;
    watch_owned(
        config,
        bytes,
        lock,
        Arc::new(tokio::sync::Semaphore::new(1)),
    )
    .await
}

/// Validate and lock the complete immutable batch before starting any issuance.
/// At most eight schedules and one issuance child; each host has its own budget.
pub async fn watch_many(paths: Vec<PathBuf>) -> Result<()> {
    ensure!(
        (1..=8).contains(&paths.len()),
        "watch-many requires 1..8 CONFIG.json files"
    );
    let mut hosts = BTreeSet::new();
    let mut states = BTreeSet::new();
    let mut inputs = Vec::new();
    for path in paths {
        let bytes = files::read(&path, 64 * 1024, false)?;
        let mut config: Config = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid ACME config schema"))?;
        config.validate(false)?;
        for name in config.dns_names() {
            ensure!(hosts.insert(name), "duplicate watch-many DNS identifier");
        }
        ensure!(
            states.insert(config.state_dir.canonicalize()?),
            "duplicate watch-many state directory"
        );
        let lock = files::Lock::acquire(config.state_dir.join(".scheduler.lock"))?;
        inputs.push((config, bytes, lock));
    }
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let mut workers = tokio::task::JoinSet::new();
    for (index, (config, bytes, lock)) in inputs.into_iter().enumerate() {
        let admission = admission.clone();
        workers.spawn(async move { (index, watch_owned(config, &bytes, lock, admission).await) });
    }
    let mut failed = false;
    while let Some(result) = workers.join_next().await {
        match result {
            Ok((index, Err(error))) => {
                failed = true;
                eprintln!(
                    "ACME schedule {index}: stopped/degraded: {error:#}; other schedules retained"
                );
            }
            Ok((index, Ok(()))) => eprintln!("ACME schedule {index}: stopped"),
            Err(error) => {
                failed = true;
                eprintln!("ACME schedule task failed: {error}");
            }
        }
    }
    ensure!(!failed, "one or more ACME schedules exhausted their budget");
    Ok(())
}

// Heartbeat has the same owner as the schedule, including long issuance waits.
// It contains only host/status metadata, never credentials or native errors.
async fn watch_owned(
    config: Config,
    bytes: &[u8],
    lock: files::Lock,
    admission: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let state = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let path = config.state_dir.join("health.json");
    let hostname = config.hostname.clone();
    let work = watch_cycle(config, bytes, lock, admission, state.clone());
    tokio::pin!(work);
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
        result=&mut work=>{write_health(&path,&hostname,if result.is_ok(){4}else{3})?;return result;},
        _=tick.tick()=>{write_health(&path,&hostname,state.load(std::sync::atomic::Ordering::Relaxed))?;}
        }
    }
}
fn write_health(path: &std::path::Path, hostname: &str, state: u8) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let state = match state {
        1 => "healthy",
        2 => "renewing",
        3 => "degraded",
        4 => "stopped",
        _ => "starting",
    };
    files::replace_secret(
        path,
        &serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"observed_at_unix_ms":now,"hostname":hostname,"state":state}),
        )?,
    )
}

async fn watch_cycle(
    config: Config,
    bytes: &[u8],
    _lock: files::Lock,
    admission: Arc<tokio::sync::Semaphore>,
    health: Arc<std::sync::atomic::AtomicU8>,
) -> Result<()> {
    let input_path = config
        .state_dir
        .join(format!(".scheduler-{}.json", files::random_id()?));
    files::write_new(&input_path, bytes)?;
    let input = Input(input_path);
    let shutdown = crate::interrupted();
    tokio::pin!(shutdown);
    let mut failures = 0;
    let mut previous = None;
    let mut ari = crate::ari::Schedule::default();
    loop {
        // Disk inspection is off the gateway hot path; same bounded file loader.
        let mut due = config.renewal_due();
        if matches!(due, Ok(false)) {
            let ari_due = tokio::select! { biased;
                signal = &mut shutdown => { signal?; return Ok(()); },
                due = ari.due(&config) => due,
            };
            if ari_due {
                due = Ok(true);
            }
        }
        let delay = match due {
            Ok(false) => {
                health.store(1, std::sync::atomic::Ordering::Relaxed);
                failures = 0;
                if previous != Some("current") {
                    eprintln!("ACME renewal: certificate current");
                    previous = Some("current");
                }
                Duration::from_secs(config.renewal.check_seconds)
            }
            decision => {
                let result = match decision {
                    Err(_) => Err(anyhow::anyhow!("renewal certificate inspection failed")),
                    Ok(true) => {
                        let _permit = tokio::select! { biased;
                            signal = &mut shutdown => { signal?; return Ok(()); },
                            permit = admission.acquire() => permit.context("ACME issuance admission closed")?,
                        };
                        health.store(2, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("ACME renewal: issuance due");
                        let mut child = tokio::process::Command::new(std::env::current_exe()?)
                            .arg(&input.0)
                            .stdin(Stdio::null())
                            .kill_on_drop(true)
                            .spawn()
                            .context("start ACME issuance child")?;
                        tokio::select! { biased;
                            signal=&mut shutdown=>{
                                signal?;
                                // Graceful child cancellation preserves DNS cleanup/journal.
                                if let Some(pid)=child.id() {
                                    let pid=nix::unistd::Pid::from_raw(i32::try_from(pid).context("child pid exceeds range")?);
                                    if nix::sys::signal::kill(pid,nix::sys::signal::Signal::SIGTERM).is_err() {
                                        eprintln!("ACME renewal child already stopped");
                                    }
                                }
                                match tokio::time::timeout(Duration::from_secs(25),child.wait()).await {
                                    Ok(result)=>{result.context("wait for cancelled ACME child")?;},
                                    Err(_)=>child.kill().await.context("stop ACME child after cleanup deadline")?,
                                }
                                eprintln!("ACME renewal supervisor stopped");
                                return Ok(());
                            },
                            result=tokio::time::timeout(Duration::from_secs(config.deadline_seconds+25),child.wait())=>{
                                match result {
                                    Ok(Ok(status)) if status.success()=>Ok(()),
                                    Ok(_)=>Err(anyhow::anyhow!("ACME renewal child failed")),
                                    Err(_)=>{child.kill().await.context("stop overdue ACME child")?;Err(anyhow::anyhow!("ACME renewal child deadline"))},
                                }
                            },
                        }
                    }
                    Ok(false) => Err(anyhow::anyhow!("renewal decision changed")),
                };
                if result.is_ok() {
                    health.store(1, std::sync::atomic::Ordering::Relaxed);
                    failures = 0;
                    previous = None;
                    eprintln!("ACME renewal: issuance committed");
                    Duration::from_secs(config.renewal.check_seconds)
                } else {
                    if let Err(error) = result {
                        eprintln!("ACME renewal: {error:#}");
                    }
                    health.store(3, std::sync::atomic::Ordering::Relaxed);
                    failures += 1;
                    previous = Some("degraded");
                    eprintln!("ACME renewal: degraded, consecutive_failures={failures}");
                    ensure!(
                        failures < config.renewal.max_failures,
                        "ACME renewal retry budget exhausted; current certificate retained"
                    );
                    config.renewal.backoff(failures)
                }
            }
        };
        tokio::select! { biased;
            result=&mut shutdown=>{result?;eprintln!("ACME renewal supervisor stopped");return Ok(());},
            _=tokio::time::sleep(delay)=>{},
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_and_configuration_are_bounded() {
        let mut config = Settings::default();
        config.validate().unwrap();
        assert_eq!(config.backoff(1).as_secs(), 30);
        assert_eq!(config.backoff(16).as_secs(), 3600);
        config.max_failures = 0;
        assert!(config.validate().is_err());
        config.max_failures = 5;
        config.check_seconds = 0;
        assert!(config.validate().is_err());
    }
}
