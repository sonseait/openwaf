//! Logical requests (each H2 stream is one request), never pooled connections.
use crate::Validation;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastActiveRequests,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub algorithm: Algorithm,
    pub slow_start_ms: u64,
}
impl Settings {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if self.slow_start_ms > 300000 {
            return Err(Validation::Endpoint);
        }
        Ok(())
    }
}
pub fn default_weight() -> u16 {
    1
}
pub fn normal_weight(weight: &u16) -> bool {
    *weight == 1
}
/// Smooth weighted round robin state is bounded to the configured 16 endpoints.
#[derive(Default)]
pub struct Selector(std::sync::Mutex<[i64; 16]>);
impl Selector {
    pub fn choose(
        &self,
        algorithm: Algorithm,
        candidates: &[(usize, u64, usize)],
        next: usize,
    ) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        if algorithm == Algorithm::LeastActiveRequests {
            // Weighted active-request load; idle/tied members use smooth
            // weights too, so slow start also applies at low concurrency.
            let best = candidates.iter().min_by(|a, b| {
                ((a.2 as u128) * u128::from(b.1)).cmp(&((b.2 as u128) * u128::from(a.1)))
            })?;
            let mut ties = [(0, 0, 0); 16];
            let mut count = 0;
            for &candidate in candidates {
                if (candidate.2 as u128) * u128::from(best.1)
                    == (best.2 as u128) * u128::from(candidate.1)
                {
                    ties[count] = candidate;
                    count += 1;
                }
            }
            return self.choose(Algorithm::WeightedRoundRobin, &ties[..count], next);
        }
        if algorithm == Algorithm::RoundRobin && candidates.iter().all(|c| c.1 == candidates[0].1) {
            return Some(candidates[next % candidates.len()].0);
        }
        let total: u64 = candidates.iter().map(|c| c.1).sum();
        if let Ok(mut scores) = self.0.try_lock() {
            for (i, score) in scores.iter_mut().enumerate() {
                if !candidates.iter().any(|c| c.0 == i) {
                    *score = 0;
                }
            }
            let mut best = candidates[0].0;
            for &(i, weight, _) in candidates {
                scores[i] += weight as i64;
                if scores[i] > scores[best] {
                    best = i;
                }
            }
            scores[best] -= total as i64;
            return Some(best);
        }
        // Contended selector never waits on a hot-path mutex. Cyclic weighted
        // fallback preserves eligibility and finite state under concurrent load.
        let mut ticket = next as u64 % total;
        for &(i, weight, _) in candidates {
            if ticket < weight {
                return Some(i);
            }
            ticket -= weight;
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn weighted_distribution_slow_endpoint_and_removed_members() {
        let selector = Selector::default();
        let candidates = [(0, 1000, 0), (1, 3000, 0)];
        let mut counts = [0; 2];
        for n in 0..400 {
            counts[selector
                .choose(Algorithm::WeightedRoundRobin, &candidates, n)
                .unwrap()] += 1;
        }
        assert_eq!(counts, [100, 300]);
        let least = Selector::default();
        let mut idle = [0; 2];
        for n in 0..400 {
            idle[least
                .choose(Algorithm::LeastActiveRequests, &candidates, n)
                .unwrap()] += 1;
        }
        assert_eq!(idle, [100, 300]);
        assert_eq!(
            selector.choose(
                Algorithm::LeastActiveRequests,
                &[(0, 1000, 8), (1, 1000, 1)],
                0
            ),
            Some(1)
        );
        for n in 0..20 {
            assert_eq!(
                selector.choose(Algorithm::WeightedRoundRobin, &[(1, 1000, 0)], n),
                Some(1)
            );
        }
        assert_eq!(selector.choose(Algorithm::RoundRobin, &[], 0), None);
    }
}
