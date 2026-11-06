//! Observe-only detector thresholds, validated before immutable publication.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub window_seconds: u64,
    pub min_samples: u32,
    pub requests_per_second: u32,
    pub distinct_paths: u32,
    pub upstream_404_percent: u32,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            min_samples: 100,
            requests_per_second: 20,
            distinct_paths: 32,
            upstream_404_percent: 50,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<(), crate::Validation> {
        if !(10..=3600).contains(&self.window_seconds)
            || !(1..=1000000).contains(&self.min_samples)
            || !(1..=100000).contains(&self.requests_per_second)
            || !(2..=64).contains(&self.distinct_paths)
            || !(1..=100).contains(&self.upstream_404_percent)
        {
            return Err(crate::Validation::Middleware);
        }
        Ok(())
    }
}
