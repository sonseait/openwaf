//! Bounded, non-blocking registration of request snapshots needing fresh health.
//! Slots hold weak snapshots: the request, not the worker, owns routing lifetime.
use crate::Snapshot;
use arc_swap::ArcSwapOption;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
};

pub const CAPACITY: usize = 256;

struct Registration {
    snapshot: Weak<Snapshot>,
    upstream: usize,
}

pub struct Requests {
    slots: Box<[ArcSwapOption<Registration>]>,
    pub health_jobs: usize,
    pub health_active: AtomicUsize,
    pub health_backlog: AtomicUsize,
    pub health_peak_backlog: AtomicUsize,
    pub health_delay_ms: AtomicU64,
    pub health_deferred: AtomicU64,
}

impl Default for Requests {
    fn default() -> Self {
        Self {
            health_jobs: 4,
            health_active: Default::default(),
            health_backlog: Default::default(),
            health_peak_backlog: Default::default(),
            health_delay_ms: Default::default(),
            health_deferred: Default::default(),
            slots: (0..CAPACITY).map(|_| ArcSwapOption::empty()).collect(),
        }
    }
}

/// Dropping the request (including timeout/cancellation) releases its slot.
pub struct Lease {
    registry: Arc<Requests>,
    index: usize,
}

impl Requests {
    pub fn new(health_jobs: usize) -> Self {
        Self {
            health_jobs,
            ..Default::default()
        }
    }
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({"jobs_limit":self.health_jobs,"active":self.health_active.load(Relaxed),"backlog":self.health_backlog.load(Relaxed),"high_water_backlog":self.health_peak_backlog.load(Relaxed),"max_scheduling_delay_ms":self.health_delay_ms.load(Relaxed),"deferred_total":self.health_deferred.load(Relaxed)})
    }
    pub fn track(self: &Arc<Self>, snapshot: &Arc<Snapshot>, route: usize) -> Option<Lease> {
        let upstream = snapshot.upstream_for_route(route)?;
        self.track_upstream(snapshot, upstream)
    }
    pub fn track_upstream(
        self: &Arc<Self>,
        snapshot: &Arc<Snapshot>,
        upstream: usize,
    ) -> Option<Lease> {
        snapshot.document.upstreams.get(upstream)?;
        let registration = Arc::new(Registration {
            snapshot: Arc::downgrade(snapshot),
            upstream,
        });
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.load().is_some() {
                continue;
            }
            let previous =
                slot.compare_and_swap(&None::<Arc<Registration>>, Some(registration.clone()));
            if previous.is_none() {
                return Some(Lease {
                    registry: self.clone(),
                    index,
                });
            }
        }
        None
    }

    /// Called by the background scheduler only; duplicate requests are collapsed.
    pub fn targets(&self) -> Vec<(Arc<Snapshot>, usize)> {
        let mut targets = Vec::new();
        for slot in &self.slots {
            let registration = slot.load();
            if let Some(registration) = &*registration
                && let Some(snapshot) = registration.snapshot.upgrade()
                && !targets.iter().any(|(old, upstream)| {
                    Arc::ptr_eq(old, &snapshot) && *upstream == registration.upstream
                })
            {
                targets.push((snapshot, registration.upstream));
            }
        }
        targets
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.registry.slots[self.index].store(None);
    }
}
