//! Public configuration contains only an authenticated encrypted Argon2id verifier.
use crate::Validation;
use serde::{Deserialize, Serialize};

pub const LOGIN_PREFIX: &str = "/.openwaf/password/";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub sealed_verifier: String,
    #[serde(default = "default_lifetime")]
    pub session_seconds: u32,
}
fn default_lifetime() -> u32 {
    43200
}
impl Policy {
    pub fn validate(&self) -> Result<(), Validation> {
        if !(300..=86400).contains(&self.session_seconds)
            || !(128..=512).contains(&self.sealed_verifier.len())
            || !self.sealed_verifier.len().is_multiple_of(2)
            || !self.sealed_verifier.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Validation::PasswordProtect);
        }
        Ok(())
    }
}
