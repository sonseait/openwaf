//! Bounded tee capture. Disk files and blocking writes belong to an owned worker;
//! proxy cancellation drops its sender, never frees storage used by the worker.
use bytes::{Bytes, BytesMut};
use openwaf_config::retry::{Replay, Storage};
use std::sync::mpsc;
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
pub struct Budget {
    memory: Arc<Semaphore>,
    disk: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    reads: Arc<Semaphore>,
    root: Option<tempfile::TempDir>,
    memory_cap: usize,
    disk_cap: usize,
    io_cap: usize,
    reserve: u64,
    io_deadline: std::time::Duration,
    peak_memory: std::sync::atomic::AtomicUsize,
    peak_disk: std::sync::atomic::AtomicUsize,
    failures: std::sync::atomic::AtomicU64,
}
impl Budget {
    #[cfg(test)]
    pub fn new() -> anyhow::Result<Arc<Self>> {
        Self::configured(&Default::default(), None, 64 * 1024 * 1024)
    }
    pub fn configured(
        b: &openwaf_config::resources::Budgets,
        directory: Option<&std::path::Path>,
        reserve: u64,
    ) -> anyhow::Result<Arc<Self>> {
        use std::os::unix::fs::PermissionsExt;
        let root = if let Some(directory) = directory {
            match std::fs::symlink_metadata(directory) {
                Ok(metadata) => {
                    anyhow::ensure!(
                        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
                        "replay directory requires a private directory (0700), no symlink"
                    );
                    tempfile::Builder::new()
                        .prefix("openwaf-replay-")
                        .tempdir_in(directory)
                        .ok()
                }
                Err(_) => None,
            }
        } else {
            tempfile::Builder::new()
                .prefix("openwaf-replay-")
                .tempdir()
                .ok()
        };
        Ok(Arc::new(Self {
            memory: Arc::new(Semaphore::new(b.replay_memory_bytes)),
            disk: Arc::new(Semaphore::new(b.replay_disk_bytes)),
            slots: Arc::new(Semaphore::new(b.replay_io_slots)),
            reads: Arc::new(Semaphore::new(b.replay_io_slots)),
            root,
            reserve,
            io_deadline: std::time::Duration::from_secs(10),
            memory_cap: b.replay_memory_bytes,
            disk_cap: b.replay_disk_bytes,
            io_cap: b.replay_io_slots,
            peak_memory: Default::default(),
            peak_disk: Default::default(),
            failures: Default::default(),
        }))
    }
    pub fn stats(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        let memory = self.memory_cap - self.memory.available_permits();
        let disk = self.disk_cap - self.disk.available_permits();
        self.peak_memory.fetch_max(memory, Relaxed);
        self.peak_disk.fetch_max(disk, Relaxed);
        serde_json::json!({"disk_available":self.root.is_some(),"unavailable_reason":if self.root.is_none(){Some("replay_directory_unavailable")}else{None},"memory_bytes":memory,"disk_bytes":disk,"high_water_memory_bytes":self.peak_memory.load(Relaxed),"high_water_disk_bytes":self.peak_disk.load(Relaxed),"io_slots":self.io_cap-self.slots.available_permits(),"read_slots":self.io_cap-self.reads.available_permits(),"minimum_free_bytes":self.reserve,"failures_total":self.failures.load(Relaxed)})
    }
}
#[derive(Default)]
struct DiskState {
    file: Option<Arc<DiskFile>>,
    complete: bool,
    failed: bool,
    reason: Option<&'static str>,
}
pub struct DiskFile {
    file: std::fs::File,
    // Reservations survive the writer and every reader/capture reference.
    _permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
}
// A timed-out/stalled syscall retains its owner/permits. Never hand those slots
// to another operation while kernel I/O still uses them.
struct Failure(Arc<Budget>, Arc<Mutex<DiskState>>);
impl Drop for Failure {
    fn drop(&mut self) {
        let mut state = self.1.lock().unwrap_or_else(|e| e.into_inner());
        if !state.complete {
            state.failed = true;
            state.file = None;
            if state.reason.is_none() {
                state.reason = Some("disk_io_unavailable");
            }
            self.0
                .failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
enum Message {
    Chunk(Bytes),
    End,
}
enum Store {
    None,
    Memory {
        bytes: BytesMut,
        frozen: Option<Bytes>,
        _permit: OwnedSemaphorePermit,
    },
    Disk {
        send: mpsc::SyncSender<Message>,
        state: Arc<Mutex<DiskState>>,
        reads: Arc<Semaphore>,
        _task: tokio::task::JoinHandle<()>,
    },
}
pub struct Capture {
    store: Store,
    cap: u64,
    seen: u64,
    ended: bool,
    pub reason: Option<&'static str>,
}
impl Default for Capture {
    fn default() -> Self {
        Self {
            store: Store::None,
            cap: 0,
            seen: 0,
            ended: false,
            reason: None,
        }
    }
}
impl Capture {
    pub fn new(policy: &Replay, budget: &Arc<Budget>) -> Self {
        let mut c = Self {
            cap: policy.cap(),
            ..Default::default()
        };
        match policy.mode {
            Storage::None => {}
            Storage::Memory => match budget.memory.clone().try_acquire_many_owned(c.cap as u32) {
                Ok(permit) => {
                    budget.peak_memory.fetch_max(
                        budget.memory_cap - budget.memory.available_permits(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    c.store = Store::Memory {
                        bytes: BytesMut::with_capacity(c.cap as usize),
                        frozen: None,
                        _permit: permit,
                    }
                }
                Err(_) => c.reason = Some("memory_quota"),
            },
            Storage::Disk => {
                if budget.root.is_none() {
                    c.reason = Some("disk_unavailable");
                    return c;
                }
                let permits = budget
                    .disk
                    .clone()
                    .try_acquire_many_owned(c.cap as u32)
                    .ok()
                    .zip(budget.slots.clone().try_acquire_owned().ok());
                if let Some(permits) = permits {
                    budget.peak_disk.fetch_max(
                        budget.disk_cap - budget.disk.available_permits(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let (send, receive) = mpsc::sync_channel::<Message>(4);
                    let state = Arc::new(Mutex::new(DiskState::default()));
                    let shared = state.clone();
                    let owner = budget.clone();
                    // Include time waiting for the blocking executor in the I/O deadline.
                    let expires = std::time::Instant::now() + owner.io_deadline;
                    let task = tokio::task::spawn_blocking(move || {
                        let _failure = Failure(owner.clone(), shared.clone());
                        let Some(root) = &owner.root else {
                            return;
                        };
                        let available = match nix::sys::statvfs::statvfs(root.path()) {
                            Ok(v) if !v.flags().contains(nix::sys::statvfs::FsFlags::ST_RDONLY) => {
                                // statvfs counters differ in width across Unix targets
                                // (available blocks are u32 on macOS, u64 on Linux).
                                #[allow(clippy::useless_conversion)]
                                let (blocks, fragment_size) = (
                                    u64::from(v.blocks_available()),
                                    u64::from(v.fragment_size()),
                                );
                                blocks.saturating_mul(fragment_size)
                            }
                            _ => return,
                        };
                        // Reserve against the entire node disk quota, avoiding concurrent
                        // jobs each relying on the same free blocks. External writers still
                        // require a dedicated filesystem/project quota at deployment.
                        if available < owner.reserve.saturating_add(owner.disk_cap as u64) {
                            shared.lock().unwrap_or_else(|e| e.into_inner()).reason =
                                Some("disk_reserve");
                            return;
                        }
                        let file = match tempfile::tempfile_in(root.path()) {
                            Ok(file) => file,
                            Err(_) => return,
                        };
                        let file = Arc::new(DiskFile {
                            file,
                            _permits: permits,
                        });
                        shared.lock().unwrap_or_else(|e| e.into_inner()).file = Some(file.clone());
                        loop {
                            if std::time::Instant::now() >= expires {
                                shared.lock().unwrap_or_else(|e| e.into_inner()).reason =
                                    Some("disk_deadline");
                                return;
                            }
                            let message = match receive.recv_timeout(
                                expires.saturating_duration_since(std::time::Instant::now()),
                            ) {
                                Ok(message) => message,
                                Err(mpsc::RecvTimeoutError::Timeout) => {
                                    shared.lock().unwrap_or_else(|e| e.into_inner()).reason =
                                        Some("disk_deadline");
                                    return;
                                }
                                Err(mpsc::RecvTimeoutError::Disconnected) => return,
                            };

                            match message {
                                Message::Chunk(bytes) => {
                                    if (&file.file).write_all(&bytes).is_err() {
                                        shared.lock().unwrap_or_else(|e| e.into_inner()).failed =
                                            true;
                                        return;
                                    }
                                }
                                Message::End => {
                                    let ok = (&file.file).flush().is_ok()
                                        && std::time::Instant::now() < expires;
                                    let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
                                    s.complete = ok;
                                    s.failed = !ok;
                                    if !ok {
                                        s.reason = Some("disk_write");
                                    }
                                    return;
                                }
                            }
                        }
                        // Anonymous storage has no directory entry, including on process death.
                    });
                    c.store = Store::Disk {
                        send,
                        state,
                        reads: budget.reads.clone(),
                        _task: task,
                    };
                } else {
                    c.reason = Some("disk_quota");
                }
            }
        }
        c
    }
    pub fn push(&mut self, chunk: &Bytes, end: bool) {
        if self.ended {
            return;
        }
        self.seen = self.seen.saturating_add(chunk.len() as u64);
        if self.seen > self.cap && !matches!(self.store, Store::None) {
            self.disable("replay_cap");
            return;
        }
        let mut failed = None;
        match &mut self.store {
            Store::None => {}
            Store::Memory { bytes, frozen, .. } => {
                bytes.extend_from_slice(chunk);
                if end {
                    *frozen = Some(bytes.split().freeze());
                }
            }
            Store::Disk { send, state, .. } => {
                let disk_failure = {
                    let state = state.lock().unwrap_or_else(|e| e.into_inner());
                    state.failed.then_some(state.reason.unwrap_or("disk_write"))
                };
                if let Some(reason) = disk_failure {
                    failed = Some(reason);
                } else {
                    for part in chunk.chunks(65536) {
                        if send
                            .try_send(Message::Chunk(Bytes::copy_from_slice(part)))
                            .is_err()
                        {
                            failed = Some("capture_queue");
                            break;
                        }
                    }
                    if end && failed.is_none() && send.try_send(Message::End).is_err() {
                        failed = Some("capture_queue");
                    }
                }
            }
        }
        if let Some(reason) = failed {
            self.disable(reason);
        }
        if end {
            self.ended = true;
        }
    }
    pub fn disable(&mut self, reason: &'static str) {
        self.store = Store::None;
        self.reason = Some(reason);
    }
    pub fn reason(&self) -> Option<&'static str> {
        self.reason.or_else(|| match &self.store {
            Store::Disk { state, .. } => {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.failed.then_some(s.reason.unwrap_or("disk_write"))
            }
            _ => None,
        })
    }
    pub fn complete(&self) -> bool {
        match &self.store {
            Store::None => false,
            Store::Memory { .. } => self.ended,
            Store::Disk { state, .. } => {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.complete && !s.failed
            }
        }
    }
    pub async fn reader(&self) -> std::io::Result<Reader> {
        if !self.complete() {
            return Err(std::io::Error::other("incomplete replay"));
        }
        match &self.store {
            Store::Memory { frozen, .. } => Ok(Reader::Memory(frozen.clone())),
            Store::Disk { state, reads, .. } => {
                let file = state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .file
                    .clone()
                    .ok_or_else(|| std::io::Error::other("replay unavailable"))?;
                Ok(Reader::Disk {
                    file,
                    offset: 0,
                    reads: reads.clone(),
                })
            }
            Store::None => Err(std::io::Error::other("no replay")),
        }
    }
}
pub enum Reader {
    Memory(Option<Bytes>),
    Disk {
        file: Arc<DiskFile>,
        offset: u64,
        reads: Arc<Semaphore>,
    },
}
impl Reader {
    pub async fn next(&mut self) -> std::io::Result<Option<Bytes>> {
        match self {
            Self::Memory(bytes) => Ok(bytes.take().filter(|b| !b.is_empty())),
            Self::Disk {
                file,
                offset,
                reads,
            } => {
                let permit = reads
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| std::io::Error::other("replay read capacity"))?;
                let file = file.clone();
                let position = *offset;
                let chunk = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::task::spawn_blocking(move || {
                        use std::os::unix::fs::FileExt;
                        let _permit = permit;
                        let mut chunk = vec![0; 65536];
                        let n = file.file.read_at(&mut chunk, position)?;
                        chunk.truncate(n);
                        Ok::<_, std::io::Error>(chunk)
                    }),
                )
                .await
                .map_err(|_| std::io::Error::other("replay reader deadline"))?
                .map_err(|_| std::io::Error::other("replay reader unavailable"))??;
                *offset += chunk.len() as u64;
                Ok((!chunk.is_empty()).then(|| Bytes::from(chunk)))
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disk_deadline_and_reader_ownership_keep_reservations_honest() {
        let mut budget = Budget::new().expect("budget");
        Arc::get_mut(&mut budget).expect("exclusive").io_deadline =
            std::time::Duration::from_millis(20);
        let c = Capture::new(
            &Replay {
                mode: Storage::Disk,
                max_body_size_bytes: Some(65536),
            },
            &budget,
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while c.reason().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("writer reports deadline within bounded scheduling allowance");
        assert!(!c.complete());
        assert_eq!(c.reason(), Some("disk_deadline"));
        assert_eq!(
            budget.disk.available_permits(),
            budget.disk_cap,
            "failed writer frees unneeded body while client is still active"
        );
        drop(c);
        let budget = Budget::new().expect("budget");
        let mut c = Capture::new(
            &Replay {
                mode: Storage::Disk,
                max_body_size_bytes: Some(65536),
            },
            &budget,
        );
        c.push(&Bytes::from_static(b"payload"), true);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !c.complete() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("complete");
        let reader = c.reader().await.expect("reader");
        drop(c);
        assert_eq!(
            budget.disk.available_permits(),
            budget.disk_cap - 65536,
            "reader still owns stored bytes and disk reservation"
        );
        drop(reader);
        assert_eq!(budget.disk.available_permits(), budget.disk_cap);
    }

    #[tokio::test]
    async fn cap_overflow_disables_replay_without_truncating_forward_input() {
        let budget = Budget::new().expect("budget");
        let mut c = Capture::new(
            &Replay {
                mode: Storage::Memory,
                max_body_size_bytes: Some(3),
            },
            &budget,
        );
        let chunk = Bytes::from_static(b"abcd");
        c.push(&chunk, true);
        assert!(!c.complete());
        assert_eq!(c.reason, Some("replay_cap"));
        assert_eq!(&chunk[..], b"abcd");
    }
    #[tokio::test]
    async fn complete_disk_replays_exact_bytes_and_cancellation_cleans() {
        let budget = Budget::new().expect("budget");
        let mut c = Capture::new(
            &Replay {
                mode: Storage::Disk,
                max_body_size_bytes: Some(65536),
            },
            &budget,
        );
        c.push(&Bytes::from_static(b"payload"), true);
        for _ in 0..100 {
            if c.complete() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        // Storage is unlinked from creation: a crash cannot leave body files.
        assert_eq!(
            std::fs::read_dir(budget.root.as_ref().expect("directory").path())
                .expect("directory")
                .count(),
            0
        );
        let mut r = c.reader().await.expect("complete");
        assert_eq!(
            r.next().await.expect("read"),
            Some(Bytes::from_static(b"payload"))
        );
        assert!(r.next().await.expect("eof").is_none());
        drop(r);
        let mut again = c.reader().await.expect("second replay");
        assert_eq!(
            again.next().await.expect("read again"),
            Some(Bytes::from_static(b"payload"))
        );
        drop(again);
        drop(c);
    }
}
