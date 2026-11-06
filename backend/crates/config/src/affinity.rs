//! Opt-in signed-cookie affinity. This is routing preference, not backend state recovery.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    Rebalance,
    Reject,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub lifetime_seconds: u32,
    pub fallback: Fallback,
}
impl Settings {
    pub fn validate(&self) -> Result<(), crate::Validation> {
        if !(1..=86400).contains(&self.lifetime_seconds) {
            return Err(crate::Validation::Endpoint);
        }
        Ok(())
    }
}
