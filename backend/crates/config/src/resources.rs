//! Startup resource envelope and route admission contract. All values have hard caps.
use crate::Validation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Admission {
    pub requests: usize,
    pub streams: usize,
    pub uploads: usize,
    pub per_client: usize,
}
impl Default for Admission {
    fn default() -> Self {
        Self {
            requests: 64,
            streams: 8,
            uploads: 4,
            per_client: 32,
        }
    }
}
impl Admission {
    /// Frozen defaults used by persisted configurations before the website quota upgrade.
    pub fn legacy_default() -> Self {
        Self {
            requests: 32,
            streams: 8,
            uploads: 4,
            per_client: 8,
        }
    }
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if self.requests == 0
            || self.requests > 128
            || self.streams > self.requests
            || self.uploads > self.requests
            || self.per_client == 0
            || self.per_client > self.requests
        {
            return Err(Validation::Resources);
        }
        Ok(())
    }
}

/// Read stored configurations with the defaults that their omitted fields meant.
/// New wire input uses current defaults; newly serialized routes pin every quota.
pub fn persisted_document(
    mut value: serde_json::Value,
) -> Result<crate::Document, serde_json::Error> {
    let legacy = Admission::legacy_default();
    if let Some(routes) = value.get_mut("routes").and_then(|v| v.as_array_mut()) {
        for route in routes {
            if let Some(route) = route.as_object_mut() {
                let admission = route.entry("admission").or_insert(serde_json::json!({}));
                if let Some(fields) = admission.as_object_mut() {
                    for (key, number) in [
                        ("requests", legacy.requests),
                        ("streams", legacy.streams),
                        ("uploads", legacy.uploads),
                        ("per_client", legacy.per_client),
                    ] {
                        fields.entry(key).or_insert(serde_json::json!(number));
                    }
                }
            }
        }
    }
    serde_json::from_value(value)
}

pub fn upgrade_defaults(document: &mut crate::Document) -> bool {
    let mut changed = false;
    for route in &mut document.routes {
        if route.admission == Admission::legacy_default() {
            route.admission = Admission::default();
            changed = true;
        }
    }
    changed
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub route: String,
    pub class: crate::traffic::Class,
    pub slots: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Budgets {
    pub reserved_routes: Vec<Reservation>,
    pub requests: usize,
    /// API, upload, stream, critical. Strict partitions: no borrowing or waiting.
    pub classes: [usize; 4],
    pub connections: usize,
    pub handshakes: usize,
    pub headers: usize,
    pub waf_workers: usize,
    pub waf_queue_per_worker: usize,
    pub health_jobs: usize,
    pub retry_slots: usize,
    pub replay_memory_bytes: usize,
    pub replay_disk_bytes: usize,
    pub replay_io_slots: usize,
    /// Accounting envelope, including an explicit native-engine allowance.
    pub ram_budget_bytes: usize,
    pub fd_budget: usize,
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            reserved_routes: vec![],
            requests: 256,
            classes: [128, 32, 64, 32],
            connections: 128,
            handshakes: 32,
            headers: 128,
            waf_workers: 2,
            waf_queue_per_worker: 4,
            health_jobs: 4,
            retry_slots: 16,
            replay_memory_bytes: 64 * 1024 * 1024,
            replay_disk_bytes: 2 * 1024 * 1024 * 1024,
            replay_io_slots: 4,
            ram_budget_bytes: 2 * 1024 * 1024 * 1024,
            fd_budget: 4096,
        }
    }
}
impl Budgets {
    pub fn estimated_ram(&self) -> usize {
        // Eight policy pools + eight shadow policy pools. Native allowance is conservative
        // accounting, not a bound on allocations inside arbitrary native rules.
        // 4 MiB/connection accounts for the H2 connection window, 32 bounded
        // stream send/header buffers and TLS/transport overhead.
        self.connections * 4 * 1024 * 1024
            + self.requests * 256 * 1024
            + 16 * self.waf_workers * (16 * 1024 * 1024 + self.waf_queue_per_worker * 128 * 1024)
            + self.replay_memory_bytes
            + self.replay_io_slots * 4 * 65536
            // Bounded route counters/windows, rollup batch and two history query responses.
            + 16 * 1024 * 1024
            // Simulator: at most eight independent single-worker pools,
            // each with one queued request and a native engine allowance.
            + 8 * (16 * 1024 * 1024 + 128 * 1024)
            // Anti-abuse: identity 4096 buckets, 1024 detector windows (64 path hashes),
            // 256 pending incidents and bounded API serialization.
            + 16 * 1024 * 1024
            // Body recorder: raw reservations, redacted cache, batches and worker.
            + 64 * 1024 * 1024
    }
    pub fn estimated_fds(&self) -> usize {
        self.connections + self.requests + self.health_jobs * 16 + self.replay_io_slots * 2 + 128
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if !(1..=256).contains(&self.requests)
            || self.classes.contains(&0)
            || self.classes.iter().any(|v| *v > self.requests)
            || self.classes.iter().sum::<usize>() > self.requests
            || !(1..=1024).contains(&self.connections)
            || !(1..=128).contains(&self.handshakes)
            || self.handshakes > self.connections
            || !(1..=256).contains(&self.headers)
            || self.headers > self.connections
            || !(1..=16).contains(&self.waf_workers)
            || !(1..=16).contains(&self.waf_queue_per_worker)
            || !(1..=16).contains(&self.health_jobs)
            || !(1..=32).contains(&self.retry_slots)
            || self.replay_memory_bytes > 64 * 1024 * 1024
            || self.replay_disk_bytes > 2 * 1024 * 1024 * 1024
            || !(1..=8).contains(&self.replay_io_slots)
            || self.ram_budget_bytes > 32usize * 1024 * 1024 * 1024
            || self.fd_budget > 16384
        {
            return Err(Validation::Resources);
        }
        if self.reserved_routes.len() > 16 {
            return Err(Validation::Resources);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut reserved = [0usize; 4];
        for r in &self.reserved_routes {
            if r.route.is_empty()
                || r.route.len() > 64
                || !r
                    .route
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !ids.insert(&r.route)
                || r.slots == 0
                || r.slots > 128
            {
                return Err(Validation::Resources);
            }
            reserved[r.class.index()] += r.slots;
        }
        if reserved.iter().zip(self.classes).any(|(r, c)| *r > c) {
            return Err(Validation::Resources);
        }
        if self.estimated_ram() > self.ram_budget_bytes || self.estimated_fds() > self.fd_budget {
            return Err(Validation::Resources);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_upgrade_preserves_custom_quotas_and_pins_stored_values() {
        let raw = serde_json::json!({"routes":[
            {"id":"web","hostname":"web.test","path":"/","path_match":"prefix"},
            {"id":"custom","hostname":"custom.test","path":"/","path_match":"prefix","admission":{"per_client":4}},
            {"id":"pinned","hostname":"pinned.test","path":"/","path_match":"prefix","admission":{"requests":128,"streams":8,"uploads":4,"per_client":64}}
        ]});
        let wire: crate::Document = serde_json::from_value(raw.clone()).expect("new wire config");
        assert_eq!(wire.routes[0].admission.requests, 64);
        assert_eq!(wire.routes[0].admission.per_client, 32);
        let mut stored = persisted_document(raw.clone()).expect("legacy stored config");
        assert_eq!(stored.routes[0].admission, Admission::legacy_default());
        assert_eq!(stored.routes[1].admission.requests, 32);
        let custom = stored.routes[1..].to_vec();
        assert!(upgrade_defaults(&mut stored));
        assert_eq!(stored.routes[0].admission, Admission::default());
        assert_eq!(stored.routes[1..], custom);
        assert!(!upgrade_defaults(&mut stored));
        let pinned = serde_json::to_value(&stored).expect("pin quotas");
        assert_eq!(pinned["routes"][0]["admission"]["per_client"], 32);
        let mut restarted = persisted_document(pinned).expect("restart");
        assert!(!upgrade_defaults(&mut restarted));
        assert_eq!(restarted, stored);
        // Old config history continues to describe the old effective quota.
        assert_eq!(
            persisted_document(raw).expect("history").routes[0]
                .admission
                .per_client,
            8
        );
        Admission::default().validate().expect("valid default");
    }
    #[test]
    fn homelab_profile_fits_envelope_and_worker_bounds_remain_finite() {
        let mut budgets: Budgets = serde_json::from_str(include_str!(
            "../../../../deploy/homelab/resource-budgets.json"
        ))
        .expect("homelab resource profile");
        budgets.validate().expect("16 CPU / 64 GiB profile");
        assert_eq!(budgets.waf_workers, 16);
        assert_eq!(budgets.waf_queue_per_worker, 16);
        assert!(budgets.estimated_fds() <= 8192);
        budgets.waf_workers = 17;
        assert!(budgets.validate().is_err());
        budgets.waf_workers = 16;
        budgets.waf_queue_per_worker = 17;
        assert!(budgets.validate().is_err());
        budgets.waf_queue_per_worker = 16;
        budgets.ram_budget_bytes = 32usize * 1024 * 1024 * 1024 + 1;
        assert!(budgets.validate().is_err());
    }
    #[test]
    fn validates_combined_envelope_before_use() {
        Budgets::default().validate().expect("defaults");
        for b in [
            Budgets {
                ram_budget_bytes: 1,
                ..Default::default()
            },
            Budgets {
                fd_budget: 32,
                ..Default::default()
            },
            Budgets {
                classes: [256; 4],
                ..Default::default()
            },
            Budgets {
                waf_workers: usize::MAX,
                ..Default::default()
            },
        ] {
            assert!(b.validate().is_err());
        }
        assert!(
            Admission {
                per_client: 65,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
