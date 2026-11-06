//! Bounded, thread-owned ModSecurity request inspection for the integration spike.
#![deny(unsafe_code)]
#[allow(unsafe_code)]
mod native;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

/// Pingora 0.9's replay buffer is 64 KiB. Larger bodies require a different replay design.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid WAF input or capacity")]
    InvalidInput,
    #[error("cannot initialize ModSecurity/rules; verify native installation and rules file")]
    Initialization,
    #[error("WAF worker initialization failed")]
    WorkerStartup,
    #[error("WAF capacity exhausted or worker unavailable")]
    Unavailable,
    #[error("WAF inspection failed")]
    Inspection,
    #[error("WAF inspection deadline exceeded")]
    Deadline,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Off = 0,
    #[default]
    DetectionOnly = 1,
    On = 2,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Configuration {
    pub mode: Mode,
    pub paranoia_level: u8,
    pub exclusions: Vec<u32>,
    pub exceptions: Vec<Exception>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Exception {
    pub rule_id: u32,
    pub target: Option<String>,
    pub expires_at_unix_ms: Option<u64>,
}
impl Configuration {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            paranoia_level: 1,
            exclusions: Vec::new(),
            exceptions: Vec::new(),
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if !(1..=4).contains(&self.paranoia_level)
            || self.exclusions.len() + self.exceptions.len() > 32
            || self.exceptions.iter().any(|e| {
                !(900000..=999999).contains(&e.rule_id)
                    || e.target
                        .as_ref()
                        .is_some_and(|t| t.len() > 160 || t.as_bytes().contains(&0))
            })
            || self
                .exclusions
                .iter()
                .any(|id| !(900000..=999999).contains(id))
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block,
}

// No Debug: avoid accidentally logging request bodies/headers/query values.
#[derive(Clone)]
pub struct Request {
    pub inspect_body: bool,
    pub uri: String,
    pub method: String,
    pub version: String,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
#[repr(C)]
pub struct Finding {
    pub rule_id: u32,
    pub phase: i32,
    pub severity: i32,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Report {
    /// True only after native request-body processing completed.
    pub body_inspected: bool,
    pub decision: Decision,
    pub findings: Vec<Finding>,
    pub truncated: bool,
    pub anomaly_score: Option<u32>,
}
struct Job {
    request: Request,
    reply: oneshot::Sender<Result<Report, Error>>,
    _permit: Ticket,
    cancelled: Arc<AtomicBool>,
    expires: Instant,
}

/// Ticket reserves native execution/queue capacity after bounded body collection. Once sent
/// to a worker, it stays held until native processing actually returns, including
/// when the caller times out or disconnects (native calls cannot be force-cancelled).
pub struct Ticket(OwnedSemaphorePermit, Option<OwnedSemaphorePermit>);
struct Cancellation(Arc<AtomicBool>);
impl Drop for Cancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Stats {
    rejected: AtomicU64,
    inspected: AtomicU64,
    blocked: AtomicU64,
    failed: AtomicU64,
    executing: AtomicUsize,
    native_micros: AtomicU64,
    timeouts: AtomicU64,
    completed_after_cancel: AtomicU64,
    peak_admitted: AtomicUsize,
    peak_queued: AtomicUsize,
    peak_executing: AtomicUsize,
}

#[derive(Debug)]
pub struct StatsSnapshot {
    pub rejected: u64,
    pub inspected: u64,
    pub blocked: u64,
    pub failed: u64,
    pub executing: usize,
    pub queued: usize,
    pub admitted: usize,
    pub native_micros: u64,
    pub timeouts: u64,
    pub completed_after_cancel: u64,
    pub executing_after_cancel: usize,
    pub peak_admitted: usize,
    pub peak_queued: usize,
    pub peak_executing: usize,
}

pub struct Pool {
    senders: Vec<mpsc::Sender<Job>>,
    workers: Vec<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    capacity: Arc<Semaphore>,
    general: Arc<Semaphore>,
    next: AtomicUsize,
    stats: Arc<Stats>,
    running: Vec<Arc<std::sync::Mutex<Option<Arc<AtomicBool>>>>>,
}

impl Pool {
    /// Each worker builds an independent native engine/ruleset on its own thread.
    pub fn new(
        path: &str,
        mode: Mode,
        workers: usize,
        queue_per_worker: usize,
    ) -> Result<Self, Error> {
        Self::configured(path, Configuration::new(mode), workers, queue_per_worker)
    }
    pub fn configured(
        path: &str,
        configuration: Configuration,
        workers: usize,
        queue_per_worker: usize,
    ) -> Result<Self, Error> {
        configuration.validate()?;
        if workers == 0 || workers > 32 || queue_per_worker == 0 || queue_per_worker > 64 {
            return Err(Error::InvalidInput);
        }
        let mut pool = Self {
            senders: Vec::new(),
            workers: Vec::new(),
            stop: Arc::new(AtomicBool::new(false)),
            capacity: Arc::new(Semaphore::new(workers * (queue_per_worker + 1))),
            general: Arc::new(Semaphore::new(
                (workers * (queue_per_worker + 1)).saturating_sub(1),
            )),
            next: AtomicUsize::new(0),
            stats: Arc::new(Stats::default()),
            running: Vec::new(),
        };
        for index in 0..workers {
            let (sender, mut receiver) = mpsc::channel::<Job>(queue_per_worker);
            let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
            let path = path.to_owned();
            let configuration = configuration.clone();
            let stop = pool.stop.clone();
            let stats = pool.stats.clone();
            let running = Arc::new(std::sync::Mutex::new(None));
            pool.running.push(running.clone());
            let handle = thread::Builder::new()
                .name(format!("waf-{index}"))
                .spawn(move || {
                    let mut engine = match native::Engine::new(&path, &configuration) {
                        Ok(engine) => {
                            if ready_sender.send(Ok(())).is_err() {
                                return;
                            }
                            engine
                        }
                        Err(error) => {
                            if ready_sender.send(Err(error)).is_err() {
                                eprintln!("WAF startup receiver closed");
                            }
                            return;
                        }
                    };
                    while let Some(job) = receiver.blocking_recv() {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        if job.reply.is_closed() || Instant::now() >= job.expires {
                            continue;
                        }
                        let executing = stats.executing.fetch_add(1, Ordering::Relaxed) + 1;
                        stats.peak_executing.fetch_max(executing, Ordering::Relaxed);
                        *running.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(job.cancelled.clone());
                        let started = Instant::now();
                        let result = engine.inspect(&job.request);
                        stats.native_micros.fetch_add(
                            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                            Ordering::Relaxed,
                        );
                        *running.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        stats.executing.fetch_sub(1, Ordering::Relaxed);
                        stats.inspected.fetch_add(1, Ordering::Relaxed);
                        match result.as_ref().map(|r| r.decision) {
                            Ok(Decision::Block) => {
                                stats.blocked.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                stats.failed.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Decision::Allow) => {}
                        }
                        // A dropped receiver means timeout/disconnect. Ownership stays
                        // on this worker until inspect has returned and tx is cleaned.
                        if job.cancelled.load(Ordering::Relaxed) {
                            stats.completed_after_cancel.fetch_add(1, Ordering::Relaxed);
                        }
                        if job.reply.send(result).is_err() {
                            stats.failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
                .map_err(|_| Error::WorkerStartup)?;
            pool.senders.push(sender);
            pool.workers.push(handle);
            ready_receiver
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Error::WorkerStartup)??;
        }
        Ok(pool)
    }

    pub fn try_reserve(&self) -> Result<Ticket, Error> {
        self.capacity
            .clone()
            .try_acquire_owned()
            .map(|permit| {
                let admitted = self
                    .senders
                    .iter()
                    .map(|sender| sender.max_capacity() + 1)
                    .sum::<usize>()
                    - self.capacity.available_permits();
                self.stats
                    .peak_admitted
                    .fetch_max(admitted, Ordering::Relaxed);
                Ticket(permit, None)
            })
            .map_err(|_| {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                Error::Unavailable
            })
    }

    /// Keep one pool slot reserved for critical routes. No borrowing and no wait.
    /// Both permits follow the job through cancellation and native cleanup.
    pub fn try_reserve_priority(&self, critical: bool) -> Result<Ticket, Error> {
        let general = if critical {
            None
        } else {
            Some(self.general.clone().try_acquire_owned().map_err(|_| {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                Error::Unavailable
            })?)
        };
        let mut ticket = self.try_reserve()?;
        ticket.1 = general;
        Ok(ticket)
    }

    pub async fn inspect(
        &self,
        ticket: Ticket,
        request: Request,
        deadline: Duration,
    ) -> Result<Decision, Error> {
        self.inspect_report(ticket, request, deadline)
            .await
            .map(|r| r.decision)
    }
    pub async fn inspect_report(
        &self,
        ticket: Ticket,
        request: Request,
        deadline: Duration,
    ) -> Result<Report, Error> {
        if !Arc::ptr_eq(ticket.0.semaphore(), &self.capacity) {
            return Err(Error::InvalidInput);
        }
        let header_bytes: usize = request.headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        if request.body.len() > MAX_BODY_BYTES
            || request.headers.len() > MAX_HEADERS
            || header_bytes > MAX_HEADER_BYTES
            || request.uri.len() > MAX_HEADER_BYTES
        {
            return Err(Error::InvalidInput);
        }
        let (reply, receive) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancellation = Cancellation(cancelled.clone());
        let mut job = Job {
            request,
            reply,
            _permit: ticket,
            cancelled,
            expires: Instant::now() + deadline,
        };
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for offset in 0..self.senders.len() {
            match self.senders[(start.wrapping_add(offset)) % self.senders.len()].try_send(job) {
                Ok(()) => {
                    let queued = self
                        .senders
                        .iter()
                        .map(|sender| sender.max_capacity() - sender.capacity())
                        .sum();
                    self.stats.peak_queued.fetch_max(queued, Ordering::Relaxed);
                    return tokio::time::timeout(deadline, receive)
                        .await
                        .map_err(|_| {
                            self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
                            Error::Deadline
                        })?
                        .map_err(|_| Error::Unavailable)?;
                }
                Err(error) => job = error.into_inner(),
            }
        }
        self.stats.rejected.fetch_add(1, Ordering::Relaxed);
        Err(Error::Unavailable)
    }

    pub fn healthy(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
            && self.workers.iter().all(|w| !w.is_finished())
            && self.senders.iter().all(|s| !s.is_closed())
    }
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            rejected: self.stats.rejected.load(Ordering::Relaxed),
            inspected: self.stats.inspected.load(Ordering::Relaxed),
            blocked: self.stats.blocked.load(Ordering::Relaxed),
            failed: self.stats.failed.load(Ordering::Relaxed),
            executing: self.stats.executing.load(Ordering::Relaxed),
            queued: self
                .senders
                .iter()
                .map(|sender| sender.max_capacity() - sender.capacity())
                .sum(),
            admitted: self
                .senders
                .iter()
                .map(|sender| sender.max_capacity() + 1)
                .sum::<usize>()
                - self.capacity.available_permits(),
            native_micros: self.stats.native_micros.load(Ordering::Relaxed),
            timeouts: self.stats.timeouts.load(Ordering::Relaxed),
            completed_after_cancel: self.stats.completed_after_cancel.load(Ordering::Relaxed),
            executing_after_cancel: self
                .running
                .iter()
                .filter(|r| {
                    r.try_lock()
                        .is_ok_and(|r| r.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)))
                })
                .count(),
            peak_admitted: self.stats.peak_admitted.load(Ordering::Relaxed),
            peak_queued: self.stats.peak_queued.load(Ordering::Relaxed),
            peak_executing: self.stats.peak_executing.load(Ordering::Relaxed),
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.capacity.close();
        self.senders.clear(); // Wake blocking receivers; skip queued work on shutdown.
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.workers.iter().any(|worker| !worker.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        for worker in self.workers.drain(..) {
            if worker.is_finished() {
                if worker.join().is_err() {
                    eprintln!("WAF worker panicked during shutdown");
                }
            } else {
                // Do not free an engine/transaction still in a native call. This
                // thread keeps ownership until it returns; process exit is the
                // final deadline. Native hard cancellation needs process isolation.
                eprintln!(
                    "WAF worker exceeded shutdown deadline; native state remains thread-owned"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(mode: Mode) -> Pool {
        Pool::new(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules.conf"),
            mode,
            1,
            1,
        )
        .expect("native test engine")
    }

    fn request(body: &[u8]) -> Request {
        Request {
            inspect_body: true,
            uri: "/submit".into(),
            method: "POST".into(),
            version: "1.1".into(),
            client: "127.0.0.1:40000".parse().expect("fixture address"),
            server: "127.0.0.1:8080".parse().expect("fixture address"),
            headers: vec![
                (b"Host".to_vec(), b"localhost".to_vec()),
                (
                    b"Content-Type".to_vec(),
                    b"application/x-www-form-urlencoded".to_vec(),
                ),
            ],
            body: body.to_vec(),
        }
    }

    #[tokio::test]
    async fn actual_native_transaction_blocks_parsed_body_only_in_on_mode() {
        for (mode, expected) in [
            (Mode::On, Decision::Block),
            (Mode::DetectionOnly, Decision::Allow),
            (Mode::Off, Decision::Allow),
        ] {
            let pool = pool(mode);
            let result = pool
                .inspect(
                    pool.try_reserve().expect("capacity"),
                    request(b"field=openwaf-test-attack"),
                    Duration::from_secs(2),
                )
                .await
                .expect("native inspection");
            assert_eq!(result, expected, "mode={mode:?}");
            assert_eq!(pool.stats().inspected, 1);
        }
    }

    #[tokio::test]
    async fn native_policy_exclusion_and_paranoia_are_isolated_between_pools() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules.conf");
        for (paranoia_level, exclusions, body, expected) in [
            (
                1,
                vec![],
                b"a=openwaf-test-attack".as_slice(),
                Decision::Block,
            ),
            (
                1,
                vec![941100],
                b"a=openwaf-test-attack".as_slice(),
                Decision::Allow,
            ),
            (2, vec![], b"a=benign".as_slice(), Decision::Block),
            (1, vec![], b"a=benign".as_slice(), Decision::Allow),
        ] {
            let pool = Pool::configured(
                path,
                Configuration {
                    mode: Mode::On,
                    paranoia_level,
                    exclusions,
                    exceptions: vec![],
                },
                1,
                1,
            )
            .expect("configured pool");
            let decision = pool
                .inspect(
                    pool.try_reserve().expect("ticket"),
                    request(body),
                    Duration::from_secs(2),
                )
                .await
                .expect("inspection");
            assert_eq!(decision, expected);
        }
    }

    #[tokio::test]
    async fn scoped_exception_expires_without_reload_and_streaming_still_checks_query() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules.conf");
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64
            + 5000;
        let mut config = Configuration::new(Mode::On);
        config.exceptions.push(Exception {
            rule_id: 941100,
            target: Some("ARGS:a".into()),
            expires_at_unix_ms: Some(expiry),
        });
        let pool = Pool::configured(path, config, 1, 1).expect("scoped policy");
        let inspect = |r| {
            pool.inspect(
                pool.try_reserve().expect("capacity"),
                r,
                Duration::from_secs(2),
            )
        };
        assert_eq!(
            inspect(request(b"a=openwaf-test-attack"))
                .await
                .expect("inspect"),
            Decision::Allow
        );
        assert_eq!(
            inspect(request(b"b=openwaf-test-attack"))
                .await
                .expect("inspect"),
            Decision::Block
        );
        // Native compilation and parallel-suite scheduling consume wall time.
        // Wait until the actual configured expiry rather than assuming setup
        // and the preceding inspections completed within a 300 ms window.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64;
        tokio::time::sleep(Duration::from_millis(expiry.saturating_sub(now) + 20)).await;
        assert_eq!(
            inspect(request(b"a=openwaf-test-attack"))
                .await
                .expect("expired"),
            Decision::Block
        );
        let mut r = request(b"a=openwaf-test-attack");
        r.inspect_body = false;
        assert_eq!(
            inspect(r.clone()).await.expect("body skipped"),
            Decision::Allow
        );
        r.uri = "/?q=openwaf-test-attack".into();
        assert_eq!(inspect(r).await.expect("query inspected"), Decision::Block);
        let mut invalid = Configuration::new(Mode::On);
        invalid.exceptions.push(Exception {
            rule_id: 999999,
            target: None,
            expires_at_unix_ms: None,
        });
        assert!(Pool::configured(path, invalid, 1, 1).is_err());
    }
    #[tokio::test]
    async fn findings_only_contain_numeric_metadata() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rules.conf"
        ))
        .expect("fixture");
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("rules.conf");
        std::fs::write(&path, source.replace("nolog", "log")).expect("write");
        let pool = Pool::new(path.to_str().expect("path"), Mode::On, 1, 1).expect("pool");
        let report = pool
            .inspect_report(
                pool.try_reserve().expect("capacity"),
                request(b"secret=openwaf-test-attack"),
                Duration::from_secs(2),
            )
            .await
            .expect("report");
        assert!(report.findings.iter().any(|f| f.rule_id == 941100));
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains("secret"));
        assert!(!json.contains("openwaf-test-attack"));
    }

    #[tokio::test]
    async fn coverage_distinguishes_early_header_block_from_body_processing() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rules.conf"
        ))
        .expect("fixture");
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("rules.conf");
        std::fs::write(&path,format!("{source}\nSecRule REQUEST_HEADERS:X-Early-Block \"@streq yes\" \"id:920001,phase:1,deny,status:403,nolog\"\n")).expect("write");
        let pool = Pool::new(path.to_str().expect("path"), Mode::On, 1, 1).expect("pool");
        for (early, inspect_body, expected) in [
            (true, true, false),
            (false, true, true),
            (false, false, false),
        ] {
            let mut input = request(b"a=benign");
            input.inspect_body = inspect_body;
            if early {
                input
                    .headers
                    .push((b"X-Early-Block".to_vec(), b"yes".to_vec()));
            }
            let report = pool
                .inspect_report(
                    pool.try_reserve().expect("capacity"),
                    input,
                    Duration::from_secs(2),
                )
                .await
                .expect("report");
            assert_eq!(report.body_inspected, expected);
            assert_eq!(
                report.decision,
                if early {
                    Decision::Block
                } else {
                    Decision::Allow
                }
            );
        }
    }

    #[tokio::test]
    async fn native_input_nul_fails_without_poisoning_worker() {
        let pool = pool(Mode::On);
        let mut invalid = request(b"a=benign");
        invalid.uri = "/bad\0uri".into();
        assert!(matches!(
            pool.inspect(
                pool.try_reserve().expect("capacity"),
                invalid,
                Duration::from_secs(2)
            )
            .await,
            Err(Error::InvalidInput)
        ));
        assert_eq!(
            pool.inspect(
                pool.try_reserve().expect("capacity"),
                request(b"a=benign"),
                Duration::from_secs(2)
            )
            .await
            .expect("worker still alive"),
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn admission_is_bounded_and_released_after_drop_or_invalid_body() {
        let pool = pool(Mode::On);
        let first = pool.try_reserve().expect("first slot");
        let second = pool.try_reserve().expect("second slot");
        assert!(matches!(pool.try_reserve(), Err(Error::Unavailable)));
        assert_eq!(pool.stats().rejected, 1);
        assert_eq!(pool.stats().peak_admitted, 2);
        drop(first);
        let replacement = pool.try_reserve().expect("released slot");
        assert!(matches!(
            pool.inspect(
                replacement,
                request(&vec![b'a'; MAX_BODY_BYTES + 1]),
                Duration::from_secs(1)
            )
            .await,
            Err(Error::InvalidInput)
        ));
        assert!(pool.try_reserve().is_ok());
        drop(second);
    }

    #[tokio::test]
    async fn critical_reservation_is_retained_until_slow_native_cleanup_after_timeout() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("rules");
        file.write_all(
            br#"SecRuleEngine On
SecRequestBodyAccess On
SecPcreMatchLimit 100000000
SecPcreMatchLimitRecursion 100000000
SecRule REQUEST_BODY "@rx ^(a|aa)+$" "id:123456,phase:2,deny,status:403,t:none"
"#,
        )
        .expect("rules");
        let pool =
            Pool::new(file.path().to_str().expect("path"), Mode::On, 1, 1).expect("native engine");
        let general = pool.try_reserve_priority(false).expect("general slot");
        assert!(pool.try_reserve_priority(false).is_err());
        let critical = pool
            .try_reserve_priority(true)
            .expect("critical reservation");
        let mut body = vec![b'a'; 4096];
        body.push(b'!');
        let result = pool
            .inspect(general, request(&body), Duration::from_millis(10))
            .await;
        assert!(
            matches!(result, Err(Error::Deadline)),
            "native fixture must outlive caller deadline: {result:?}"
        );
        assert_eq!(
            pool.stats().executing_after_cancel,
            1,
            "native code is still executing after caller timeout"
        );
        assert!(
            pool.try_reserve_priority(false).is_err(),
            "timeout cannot recycle native admission"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.stats().executing > 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("native match limit bounds fixture");
        assert_eq!(pool.stats().completed_after_cancel, 1);
        drop(critical);
        pool.try_reserve_priority(false)
            .expect("native cleanup releases capacity");
    }

    #[tokio::test]
    async fn expired_native_work_does_not_run_and_does_not_leak_capacity() {
        let pool = pool(Mode::On);
        let ticket = pool.try_reserve().expect("slot");
        assert!(matches!(
            pool.inspect(ticket, request(b"a=benign"), Duration::ZERO)
                .await,
            Err(Error::Unavailable | Error::Deadline)
        ));
        // Caller cancellation can precede the worker draining the expired job.
        // Wait for ownership cleanup, rather than assuming synchronous release.
        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.capacity.available_permits() != 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("expired work released its ticket");
        assert_eq!(pool.stats().inspected, 0);
    }

    #[test]
    fn concurrent_native_lifecycle_and_inspection_is_safe() {
        let threads: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .expect("test runtime");
                    for _ in 0..4 {
                        let pool = pool(Mode::On);
                        runtime.block_on(async {
                            for _ in 0..8 {
                                assert_eq!(
                                    pool.inspect(
                                        pool.try_reserve().expect("slot"),
                                        request(b"a=benign"),
                                        Duration::from_secs(2)
                                    )
                                    .await
                                    .expect("concurrent native call"),
                                    Decision::Allow
                                );
                            }
                        });
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("lifecycle thread");
        }
    }

    #[test]
    fn invalid_startup_is_reported_and_partial_pool_is_cleaned_up() {
        assert!(matches!(
            Pool::new("/missing/openwaf-rules", Mode::On, 1, 1),
            Err(Error::Initialization)
        ));
        assert!(matches!(
            Pool::new("/unused", Mode::On, 0, 1),
            Err(Error::InvalidInput)
        ));
    }
}
