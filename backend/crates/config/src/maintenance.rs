//! Persistent per-route maintenance policy. Applied through configuration snapshots.
use crate::Validation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_message")]
    pub message: String,
    #[serde(default = "default_retry")]
    pub retry_after_seconds: u32,
}
fn default_message() -> String {
    "We are performing scheduled maintenance. Please try again shortly.".into()
}
fn default_retry() -> u32 {
    300
}
impl Policy {
    pub fn validate(&self) -> Result<(), Validation> {
        if self.message.trim().is_empty()
            || self.message.len() > 512
            || self.message.chars().any(|c| c.is_control() && c != '\n')
            || !(1..=86400).contains(&self.retry_after_seconds)
        {
            return Err(Validation::Maintenance);
        }
        Ok(())
    }
}
