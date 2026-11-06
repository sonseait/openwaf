//! Node-local endpoint admission. Persistence belongs to the control plane.
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::watch;
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Active,
    Drain,
    Maintenance,
}
pub struct Entry {
    pub deadline_unix_ms: Option<u64>,
    pub resumed_at: Option<std::time::Instant>,
    pub mode: Mode,
    pub revision: i64,
    pub reason: String,
    pub active: Arc<AtomicUsize>,
    pub force: watch::Sender<u64>,
}
#[derive(Default)]
pub struct Operations {
    entries: ArcSwap<BTreeMap<String, Arc<Entry>>>,
    mutation: std::sync::Mutex<()>,
}
pub struct Lease {
    entry: Arc<Entry>,
    cancellation: watch::Receiver<u64>,
}
impl Lease {
    pub fn cancellation(&self) -> watch::Receiver<u64> {
        self.cancellation.clone()
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.entry.active.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Operations {
    pub fn reconcile(&self, documents: &[&crate::Document]) {
        let _lock = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        let keys: std::collections::BTreeSet<_> = documents
            .iter()
            .flat_map(|document| document.upstreams.iter())
            .flat_map(|u| u.endpoints.iter().map(|e| Self::key(&u.id, e)))
            .collect();
        let mut map = (**self.entries.load()).clone();
        map.retain(|key, e| {
            keys.contains(key) || e.revision > 0 || e.active.load(Ordering::Relaxed) > 0
        });
        for key in keys {
            map.entry(key).or_insert_with(|| {
                Arc::new(Entry {
                    deadline_unix_ms: None,
                    resumed_at: None,
                    mode: Mode::Active,
                    revision: 0,
                    reason: String::new(),
                    active: Arc::new(AtomicUsize::new(0)),
                    force: watch::channel(0).0,
                })
            });
        }
        self.entries.store(Arc::new(map));
    }

    pub fn key(upstream: &str, endpoint: &crate::Endpoint) -> String {
        let key = format!(
            "{upstream}|{:?}|{}|{}",
            endpoint.protocol,
            endpoint.address.0.as_str(),
            endpoint.tls_server_name.as_deref().unwrap_or("")
        );
        if endpoint.tls_verify {
            key
        } else {
            format!("{key}|tls-unverified")
        }
    }
    pub fn eligible(&self, key: &str) -> bool {
        self.entries
            .load()
            .get(key)
            .is_none_or(|e| e.mode == Mode::Active)
    }
    pub fn acquire(&self, key: &str) -> Option<Lease> {
        let e = self.entries.load().get(key).cloned()?;
        if e.mode != Mode::Active {
            return None;
        }
        let cancellation = e.force.subscribe();
        e.active.fetch_add(1, Ordering::Relaxed);
        // Recheck after increment: a concurrent drain sees this lease or the
        // admission is refused. No hot-path lock and no silent post-drain lease.
        if !self.entries.load().get(key).is_some_and(|current| {
            current.mode == Mode::Active && Arc::ptr_eq(&current.active, &e.active)
        }) {
            e.active.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Lease {
            cancellation,
            entry: e,
        })
    }
    pub fn set(&self, key: String, mode: Mode, revision: i64, reason: String) {
        self.set_with_deadline(key, mode, revision, reason, None);
    }
    pub fn set_with_deadline(
        &self,
        key: String,
        mode: Mode,
        revision: i64,
        reason: String,
        deadline_unix_ms: Option<u64>,
    ) {
        let _lock = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        let mut map = (**self.entries.load()).clone();
        if map.get(&key).is_some_and(|e| e.revision >= revision) {
            return;
        }
        let old = map.get(&key);
        let entry = Arc::new(Entry {
            deadline_unix_ms,
            resumed_at: if mode == Mode::Active && old.is_some_and(|e| e.mode != Mode::Active) {
                Some(std::time::Instant::now())
            } else {
                old.and_then(|e| e.resumed_at)
            },
            mode,
            revision,
            reason,
            active: old.map_or_else(|| Arc::new(AtomicUsize::new(0)), |e| e.active.clone()),
            force: old.map_or_else(|| watch::channel(0).0, |e| e.force.clone()),
        });
        map.insert(key, entry);
        self.entries.store(Arc::new(map));
    }
    pub fn load(&self, key: &str, slow_start_ms: u64) -> (usize, u64) {
        self.entries.load().get(key).map_or((0, 1000), |e| {
            let progress = if slow_start_ms == 0 {
                1000
            } else {
                e.resumed_at.map_or(1000, |t| {
                    ((t.elapsed().as_millis() * 1000 / u128::from(slow_start_ms)).min(1000) as u64)
                        .max(1)
                })
            };
            (e.active.load(Ordering::Relaxed), progress)
        })
    }
    pub fn force(&self, key: &str) -> bool {
        let map = self.entries.load();
        let Some(e) = map.get(key) else {
            return false;
        };
        e.force.send_modify(|v| *v = v.wrapping_add(1));
        true
    }
    pub fn status(&self) -> serde_json::Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        serde_json::Value::Array(self.entries.load().iter().map(|(key,e)|serde_json::json!({"key":key,"mode":e.mode,"revision":e.revision,"reason":e.reason,"active_requests":e.active.load(Ordering::Relaxed),"remaining_leases":e.active.load(Ordering::Relaxed),"deadline_unix_ms":e.deadline_unix_ms,"deadline_exceeded":e.deadline_unix_ms.is_some_and(|v|v<=now),"drained":e.mode!=Mode::Active && e.active.load(Ordering::Relaxed)==0})).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drain_lease_deadline_force_scope_and_recovery() {
        let ops = Operations::default();
        ops.set("a".into(), Mode::Active, 1, "ready".into());
        ops.set("b".into(), Mode::Active, 1, "ready".into());
        let lease = ops.acquire("a").unwrap();
        let mut cancel = lease.cancellation();
        let sibling = ops.acquire("b").unwrap();
        let other = sibling.cancellation();
        ops.set_with_deadline("a".into(), Mode::Drain, 2, "maintenance".into(), Some(1));
        assert!(!ops.eligible("a"));
        assert!(ops.acquire("a").is_none());
        assert_eq!(ops.load("a", 1000).0, 1);
        assert!(!cancel.has_changed().unwrap());
        assert_eq!(ops.status()[0]["deadline_exceeded"], true);
        assert!(ops.force("a"));
        assert!(cancel.has_changed().unwrap());
        assert!(!other.has_changed().unwrap());
        cancel.borrow_and_update();
        drop(lease);
        assert_eq!(ops.status()[0]["drained"], true);
        ops.set("a".into(), Mode::Active, 3, "recovered".into());
        assert!(ops.load("a", 300000).1 < 1000);
        ops.set("a".into(), Mode::Maintenance, 2, "stale".into());
        assert!(ops.eligible("a"));
    }
}
