//! Declarative immutable release target; artifacts are prepared by the control plane.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Static,
    Spa,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub application_id: String,
    pub release_id: String,
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_expires_at_unix_ms: Option<u64>,
}
pub fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Target {
    pub fn validate(&self) -> Result<(), crate::Validation> {
        if !valid_id(&self.application_id)
            || !valid_id(&self.release_id)
            || self.preview_expires_at_unix_ms == Some(0)
        {
            return Err(crate::Validation::Application);
        }
        Ok(())
    }
}
