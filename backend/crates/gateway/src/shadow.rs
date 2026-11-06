//! Separate shadow compiler and workers, bounded copies and no upstream client.
use arc_swap::ArcSwapOption;
use openwaf_admin::{
    config::Preparer,
    shadow::{Backend, Start},
};
use openwaf_waf::{Decision, Pool, Request};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

fn sample_bucket(id: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish() % 100
}

struct Session {
    route: String,
    inspection_scope: String,
    body_limit: usize,
    inspection_timeout: Duration,
    scopes: Mutex<std::collections::BTreeMap<&'static str, u64>>,
    findings_untracked: AtomicU64,
    version: i64,
    sampling: u8,
    expires: Instant,
    started: u64,
    duration_ms: u64,
    pool: Arc<Pool>,
    active: AtomicBool,
    sampled: AtomicU64,
    completed: AtomicU64,
    would_block: AtomicU64,
    differed: AtomicU64,
    dropped: AtomicU64,
    findings: Mutex<std::collections::BTreeMap<u32, u64>>,
}
struct Job {
    session: Arc<Session>,
    request: Request,
    actual: bool,
    scope: &'static str,
}
pub struct Service {
    epoch: u64,
    current: ArcSwapOption<Session>,
    compiler: crate::waf_policy::Compiler,
    send: mpsc::Sender<Job>,
    receive: tokio::sync::Mutex<mpsc::Receiver<Job>>,
    starting: tokio::sync::Mutex<()>,
}
impl Service {
    pub fn new(path: String, workers: usize, queue: usize) -> anyhow::Result<Arc<Self>> {
        let config = openwaf_waf::Configuration::new(openwaf_waf::Mode::On);
        let pool = Arc::new(Pool::configured(&path, config.clone(), workers, queue)?);
        let compiler =
            crate::waf_policy::Compiler::with_budgets(path, config, pool, workers, queue)?;
        let (send, receive) = mpsc::channel(4);
        Ok(Arc::new(Self {
            epoch: openwaf_telemetry::now_ms(),
            current: ArcSwapOption::empty(),
            compiler,
            send,
            receive: tokio::sync::Mutex::new(receive),
            starting: tokio::sync::Mutex::new(()),
        }))
    }
    pub fn interested(&self, route: &str, id: &str, version: i64) -> bool {
        self.current.load().as_ref().is_some_and(|s| {
            s.active.load(Relaxed)
                && s.expires > Instant::now()
                && s.route == route
                && s.version == version
                && sample_bucket(id) < u64::from(s.sampling)
        })
    }
    pub fn offer(
        &self,
        route: &str,
        id: &str,
        request: &Request,
        actual: bool,
        version: i64,
        scope: &'static str,
    ) {
        let Some(session) = self.current.load_full() else {
            return;
        };
        if !session.active.load(Relaxed)
            || session.expires <= Instant::now()
            || session.route != route
            || session.version != version
        {
            return;
        }
        let bucket = sample_bucket(id);
        if bucket >= u64::from(session.sampling) {
            return;
        }
        session.sampled.fetch_add(1, Relaxed);
        if request.body.len() > session.body_limit {
            session.dropped.fetch_add(1, Relaxed);
            return;
        }
        // Request buffers are bounded by primary admission; streamed bodies stay empty.
        let job = Job {
            session: session.clone(),
            request: request.clone(),
            actual,
            scope,
        };
        if self.send.try_send(job).is_err() {
            session.dropped.fetch_add(1, Relaxed);
        }
    }
}
#[async_trait::async_trait]
impl Backend for Service {
    async fn start(&self, input: Start, version: i64) -> Result<serde_json::Value, ()> {
        let _guard = self.starting.try_lock().map_err(|_| ())?;
        if self
            .current
            .load()
            .as_ref()
            .is_some_and(|s| s.active.load(Relaxed) && s.expires > Instant::now())
        {
            return Err(());
        }
        let mut policy = input.policy;
        policy.mode = openwaf_config::waf::Mode::On;
        let document=serde_json::from_value(serde_json::json!({"routes":[{"id":input.route_id,"hostname":"shadow.invalid","path":"/","path_match":"prefix","redirect":{"url":"https://outside.invalid/","status":302},"waf":policy}]})).map_err(|_|())?;
        let snapshot = openwaf_config::Snapshot::prepare(
            version,
            document,
            &openwaf_config::Context {
                listeners: vec![],
                local_ips: vec![],
            },
        )
        .map_err(|_| ())?;
        let snapshot = self
            .compiler
            .client
            .prepare(snapshot)
            .await
            .map_err(|_| ())?;
        let pool = snapshot
            .prepared
            .as_ref()
            .and_then(|p| p.downcast_ref::<crate::waf_policy::Prepared>())
            .and_then(|p| p.routes.first())
            .and_then(|p| p.clone())
            .ok_or(())?;
        let session = Session {
            route: snapshot.document.routes[0].id.clone(),
            inspection_scope: input.inspection_scope,
            body_limit: snapshot.document.routes[0]
                .waf
                .as_ref()
                .map_or(65536, |p| p.body_limit_bytes),
            inspection_timeout: Duration::from_millis(
                snapshot.document.routes[0]
                    .waf
                    .as_ref()
                    .map_or(2000, |p| p.inspection_timeout_ms),
            ),
            scopes: Mutex::new(Default::default()),
            findings_untracked: AtomicU64::new(0),
            version,
            sampling: input.sampling_percent,
            expires: Instant::now() + Duration::from_millis(input.duration_ms),
            started: openwaf_telemetry::now_ms(),
            duration_ms: input.duration_ms,
            pool,
            active: AtomicBool::new(true),
            sampled: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            would_block: AtomicU64::new(0),
            differed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            findings: Mutex::new(Default::default()),
        };
        self.current.store(Some(Arc::new(session)));
        Ok(self.status())
    }
    fn status(&self) -> serde_json::Value {
        self.current.load().as_ref().map_or_else(||serde_json::json!({"state":"idle","process_epoch":self.epoch}), |s| {
            let sampled = s.sampled.load(Relaxed);
            let completed = s.completed.load(Relaxed);
            let dropped = s.dropped.load(Relaxed);
            serde_json::json!({
                "state":if !s.active.load(Relaxed){"stopped"}else if Instant::now()>=s.expires{"completed"}else{"running"},
                "process_epoch":self.epoch,"route_id":s.route,"config_version":s.version,"sampling_percent":s.sampling,
                "started_at_unix_ms":s.started,"ends_at_unix_ms":s.started.saturating_add(s.duration_ms),"duration_ms":s.duration_ms,
                "sampled":sampled,"completed":completed,"dropped":dropped,"pending":sampled.saturating_sub(completed.saturating_add(dropped)),
                "comparison_denominator":completed,"sampling_population":"primary_waf_result_or_off_after_contract_checks","comparison_basis":"completed_shadow_vs_actual_primary_decision",
                "inspection_scope":s.inspection_scope,"completed_scopes":*s.scopes.lock().unwrap_or_else(|e|e.into_inner()),
                "would_block":s.would_block.load(Relaxed),"different_decisions":s.differed.load(Relaxed),
                "findings":*s.findings.lock().unwrap_or_else(|e|e.into_inner()),"findings_untracked":s.findings_untracked.load(Relaxed),
                "conclusion_limited":completed==0 || dropped>0,"source":"real_traffic","extra_upstream_requests":0,"matched_data_collected":false,
                "restart_behavior":"session_and_counters_reset"
            })
        })
    }
    fn stop(&self) {
        if let Some(s) = self.current.load().as_ref() {
            s.active.store(false, Relaxed);
        }
    }
    async fn run(&self) {
        let mut receive = self.receive.lock().await;
        while let Some(job) = receive.recv().await {
            let s = job.session;
            if !s.active.load(Relaxed) || Instant::now() >= s.expires {
                s.dropped.fetch_add(1, Relaxed);
                continue;
            }
            let Ok(ticket) = s.pool.try_reserve() else {
                s.dropped.fetch_add(1, Relaxed);
                continue;
            };
            match s
                .pool
                .inspect_report(ticket, job.request, s.inspection_timeout)
                .await
            {
                Ok(report) => {
                    let scope = if !report.body_inspected && job.scope == "full" {
                        "headers_query_only"
                    } else {
                        job.scope
                    };
                    *s.scopes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .entry(scope)
                        .or_default() += 1;
                    s.completed.fetch_add(1, Relaxed);
                    let block = report.decision == Decision::Block;
                    if block {
                        s.would_block.fetch_add(1, Relaxed);
                    }
                    if block != job.actual {
                        s.differed.fetch_add(1, Relaxed);
                    }
                    let mut findings = s.findings.lock().unwrap_or_else(|e| e.into_inner());
                    for f in report.findings {
                        if findings.contains_key(&f.rule_id) || findings.len() < 32 {
                            *findings.entry(f.rule_id).or_default() += 1;
                        } else {
                            s.findings_untracked.fetch_add(1, Relaxed);
                        }
                    }
                }
                Err(_) => {
                    s.dropped.fetch_add(1, Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_case_ids_do_not_collapse_into_one_sampling_bucket() {
        let buckets: std::collections::BTreeSet<_> = (0..256)
            .map(|i| {
                let id = format!("Mixed_Case_Reference_{i:012}");
                let bucket = sample_bucket(&id);
                assert_eq!(bucket, sample_bucket(&id));
                assert!(bucket < 100);
                bucket
            })
            .collect();
        assert!(buckets.len() > 50);
        assert!(buckets.iter().any(|bucket| *bucket < 10));
        assert!(buckets.iter().any(|bucket| *bucket >= 10));
    }

    #[tokio::test]
    async fn sample_loss_version_boundary_stop_and_small_candidate_body_are_explicit() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../waf/tests/fixtures/rules.conf"
        );
        let service = Service::new(path.into(), 1, 1).unwrap();
        service
            .start(
                Start {
                    route_id: "app".into(),
                    policy: Default::default(),
                    sampling_percent: 100,
                    duration_ms: 60000,
                    inspection_scope: "full_except_multipart".into(),
                },
                1,
            )
            .await
            .unwrap();
        let request = Request {
            inspect_body: true,
            uri: "/".into(),
            method: "GET".into(),
            version: "1.1".into(),
            client: "127.0.0.1:1234".parse().unwrap(),
            server: "127.0.0.1:8080".parse().unwrap(),
            headers: vec![],
            body: vec![],
        };
        for _ in 0..20 {
            service.offer("app", "00000000", &request, false, 1, "full");
        }
        let status = service.status();
        assert_eq!(status["sampled"], 20);
        assert_eq!(status["dropped"], 16);
        assert_eq!(status["pending"], 4);
        assert_eq!(status["comparison_denominator"], 0);
        assert_eq!(status["conclusion_limited"], true);
        service.offer("app", "00000000", &request, false, 2, "full");
        assert_eq!(service.status()["sampled"], 20);
        service.stop();
        service.offer("app", "00000000", &request, false, 1, "full");
        assert_eq!(service.status()["sampled"], 20);
        service
            .start(
                Start {
                    route_id: "app".into(),
                    policy: openwaf_config::waf::Policy {
                        body_limit_bytes: 1,
                        ..Default::default()
                    },
                    sampling_percent: 100,
                    duration_ms: 60000,
                    inspection_scope: "full_except_multipart".into(),
                },
                2,
            )
            .await
            .unwrap();
        let mut large = request;
        large.body = vec![1; 2];
        service.offer("app", "00000000", &large, false, 2, "full");
        assert_eq!(service.status()["dropped"], 1);
        // A fresh process never claims a previous session's counters are complete.
        assert_eq!(
            Service::new(path.into(), 1, 1).unwrap().status()["state"],
            "idle"
        );
    }
}
