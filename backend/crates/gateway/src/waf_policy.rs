//! Native resource preparation and retirement on one owned management thread.
//! The registry always owns pools while proxy snapshots can reference them, so
//! dropping the last request never joins workers or frees native engines.
use anyhow::{Context, Result};
use openwaf_admin::config::{PreparationUnavailable, Preparer};
use openwaf_config::{Snapshot, waf};
use openwaf_waf::{Configuration, Mode, Pool};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

pub const MAX_POOLS: usize = 8;
pub struct Prepared {
    pub routes: Vec<Option<Arc<Pool>>>,
}
struct Job {
    snapshot: Snapshot,
    reply: oneshot::Sender<std::result::Result<Snapshot, PreparationUnavailable>>,
    expires: Instant,
}
pub struct Client {
    send: mpsc::SyncSender<Job>,
    stop: Arc<AtomicBool>,
    stats: Arc<std::sync::Mutex<serde_json::Value>>,
}
pub struct Compiler {
    pub client: Arc<Client>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

pub fn mode(policy: &waf::Policy) -> Mode {
    match policy.mode {
        waf::Mode::Off => Mode::Off,
        waf::Mode::DetectionOnly => Mode::DetectionOnly,
        waf::Mode::On => Mode::On,
    }
}
pub fn configuration(policy: &waf::Policy) -> Configuration {
    Configuration {
        mode: mode(policy),
        paranoia_level: policy.paranoia_level,
        exclusions: vec![],
        exceptions: policy
            .exclusions
            .iter()
            .map(|e| openwaf_waf::Exception {
                rule_id: e.rule_id,
                target: e.target.clone(),
                expires_at_unix_ms: e.expires_at_unix_ms,
            })
            .collect(),
    }
}
impl Compiler {
    #[cfg(test)]
    pub fn start(path: String, legacy: Configuration, pool: Arc<Pool>) -> Result<Self> {
        Self::with_budgets(path, legacy, pool, 2, 4)
    }
    pub fn with_budgets(
        path: String,
        legacy: Configuration,
        pool: Arc<Pool>,
        workers: usize,
        queue: usize,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (send, receive) = mpsc::sync_channel::<Job>(2);
        let stats = Arc::new(std::sync::Mutex::new(
            serde_json::json!({"available":false}),
        ));
        let shared = stats.clone();
        let client = Arc::new(Client {
            send,
            stop: stop.clone(),
            stats,
        });
        let worker = thread::Builder::new()
            .name("waf-policy-compiler".into())
            .spawn(move || {
                let mut pools = vec![(legacy.clone(), pool)];
                while !stopped.load(Ordering::Acquire) {
                    pools.retain(|(_, pool)| Arc::strong_count(pool) > 1 || pool.stats().admitted > 0);
                    let states: Vec<_> = pools.iter().map(|(_,pool)|pool.stats()).collect();
                    *shared.lock().unwrap_or_else(|e|e.into_inner()) = serde_json::json!({"available":true,"observed_at_unix_ms":openwaf_telemetry::now_ms(),"pools":pools.len(),"retired_pools":pools.iter().filter(|(_,p)|Arc::strong_count(p)==1).count(),"executing":states.iter().map(|s|s.executing).sum::<usize>(),"queued":states.iter().map(|s|s.queued).sum::<usize>(),"admitted":states.iter().map(|s|s.admitted).sum::<usize>(),"executing_after_cancel":states.iter().map(|s|s.executing_after_cancel).sum::<usize>(),"completed_after_cancel":states.iter().map(|s|s.completed_after_cancel).sum::<u64>()});

                    let job = match receive.recv_timeout(Duration::from_millis(100)) {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    if job.reply.is_closed() || Instant::now() >= job.expires {
                        continue;
                    }
                    // Pools can only be retired here, outside every proxy executor.
                    pools.retain(|(_, pool)| Arc::strong_count(pool) > 1 || pool.stats().admitted > 0);
                    let mut snapshot = job.snapshot;
                    let mut routes = Vec::with_capacity(snapshot.document.routes.len());
                    let mut failed = false;
                    let mut invalid = false;
                    for route in &snapshot.document.routes {
                        if stopped.load(Ordering::Acquire)
                            || job.reply.is_closed()
                            || Instant::now() >= job.expires
                        {
                            failed = true;
                            break;
                        }
                        let config = route
                            .waf
                            .as_ref()
                            .map(configuration)
                            .unwrap_or_else(|| legacy.clone());
                        if config.mode == Mode::Off {
                            routes.push(None);
                            continue;
                        }
                        let pool = match pools.iter().find(|(key, _)| key == &config) {
                            Some((_, pool)) => pool.clone(),
                            None if pools.len() < MAX_POOLS => {
                                match Pool::configured(&path, config.clone(), workers, queue) {
                                    Ok(pool) => {
                                        let pool = Arc::new(pool);
                                        pools.push((config, pool.clone()));
                                        pool
                                    }
                                    Err(error) => {
                                        invalid = matches!(error, openwaf_waf::Error::InvalidInput);
                                        failed = true;
                                        break;
                                    }
                                }
                            }
                            None => {
                                failed = true;
                                break;
                            }
                        };
                        routes.push(Some(pool));
                    }
                    let result = if failed || Instant::now() >= job.expires {
                        Err(if invalid {
                            PreparationUnavailable::InvalidPolicy
                        } else {
                            PreparationUnavailable::Unavailable
                        })
                    } else {
                        snapshot.prepared = Some(Arc::new(Prepared { routes }));
                        Ok(snapshot)
                    };
                    // Cancellation simply discards the prepared snapshot; registry
                    // ownership keeps cleanup on this compiler's next collection.
                    let _ = job.reply.send(result);
                }
                // Normal owner shutdown happens after proxy drain and admin shutdown.
                drop(pools);
            })
            .context("start WAF policy compiler")?;
        Ok(Self {
            client,
            stop,
            worker: Some(worker),
        })
    }
}
impl Client {
    pub fn stats(&self) -> serde_json::Value {
        self.stats.try_lock().map(|s| s.clone()).unwrap_or_else(
            |_| serde_json::json!({"available":false,"reason":"compiler_stats_contention"}),
        )
    }
}
#[async_trait::async_trait]
impl Preparer for Client {
    async fn prepare(
        &self,
        snapshot: Snapshot,
    ) -> std::result::Result<Snapshot, PreparationUnavailable> {
        if self.stop.load(Ordering::Acquire) {
            return Err(PreparationUnavailable::Unavailable);
        }
        let (reply, received) = oneshot::channel();
        self.send
            .try_send(Job {
                snapshot,
                reply,
                expires: Instant::now() + Duration::from_secs(10),
            })
            .map_err(|_| PreparationUnavailable::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(10), received)
            .await
            .map_err(|_| PreparationUnavailable::Unavailable)?
            .map_err(|_| PreparationUnavailable::Unavailable)?
    }
}
impl Drop for Compiler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                if worker.join().is_err() {
                    eprintln!("WAF compiler owner panicked");
                }
            } else {
                eprintln!(
                    "WAF compiler exceeded shutdown deadline; native ownership remains on its worker"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(rule: Option<u32>) -> Snapshot {
        let mut policy = waf::Policy {
            mode: waf::Mode::On,
            ..Default::default()
        };
        if let Some(rule_id) = rule {
            policy.exclusions.push(waf::Exclusion {
                owner: None,
                rule_id: 941100,
                reason: "Test exception".into(),
                target: None,
                expires_at_unix_ms: Some(2000000000000 + u64::from(rule_id)),
            });
        }
        let document = serde_json::from_value(serde_json::json!({"routes": [{"id": "app", "hostname": "app.test", "path": "/", "path_match": "prefix", "redirect": {"url": "https://outside.invalid/", "status": 308}, "waf": policy}]})).expect("document");
        Snapshot::prepare(
            1,
            document,
            &openwaf_config::Context {
                listeners: vec![],
                local_ips: vec![],
            },
        )
        .expect("snapshot")
    }
    fn compiler() -> Compiler {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../waf/tests/fixtures/rules.conf"
        );
        let pool = Arc::new(Pool::new(path, Mode::On, 1, 1).expect("pool"));
        // Keep the seed in a prepared snapshot in the test, as main keeps it in
        // Gateway. For the bound test every compiled entry is explicitly pinned.
        Compiler::start(path.into(), Configuration::new(Mode::On), pool).expect("compiler")
    }
    fn pool(snapshot: &Snapshot) -> &Arc<Pool> {
        snapshot
            .prepared
            .as_ref()
            .expect("prepared")
            .downcast_ref::<Prepared>()
            .expect("type")
            .routes[0]
            .as_ref()
            .expect("pool")
    }
    #[tokio::test]
    async fn retained_snapshots_bound_native_pools_and_retirement_releases_capacity() {
        let compiler = compiler();
        let mut held = Vec::new();
        for index in 0..MAX_POOLS {
            held.push(
                compiler
                    .client
                    .prepare(snapshot(Some(941100 + index as u32)))
                    .await
                    .expect("capacity"),
            );
        }
        assert!(
            compiler
                .client
                .prepare(snapshot(Some(941200)))
                .await
                .is_err()
        );
        let duplicate = compiler
            .client
            .prepare(snapshot(Some(941100)))
            .await
            .expect("reuse existing");
        assert!(Arc::ptr_eq(pool(&held[0]), pool(&duplicate)));
        held.pop();
        let replacement = compiler
            .client
            .prepare(snapshot(Some(941200)))
            .await
            .expect("retired pool releases capacity");
        assert!(!Arc::ptr_eq(pool(&replacement), pool(&duplicate)));
        // All snapshots must be released before owner shutdown, like proxy drain.
        drop(replacement);
        drop(duplicate);
        drop(held);
    }
    #[tokio::test]
    async fn canceled_preparation_does_not_poison_the_owner_or_publish_resources() {
        let compiler = compiler();
        let (reply, receiver) = oneshot::channel();
        drop(receiver);
        assert!(
            compiler
                .client
                .send
                .try_send(Job {
                    snapshot: snapshot(Some(941100)),
                    reply,
                    expires: Instant::now() + Duration::from_secs(1)
                })
                .is_ok()
        );
        let prepared = compiler
            .client
            .prepare(snapshot(None))
            .await
            .expect("compiler remains usable");
        assert!(prepared.prepared.is_some());
        drop(prepared);
    }
}
