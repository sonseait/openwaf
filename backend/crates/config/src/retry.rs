//! Retry authorization is independent of body replay capability.
use crate::Validation;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Disabled,
    ConnectOnly,
    Safe,
    Idempotent,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Storage {
    #[default]
    None,
    Memory,
    Disk,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Endpoint,
    Pool,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    ConnectFailure,
    ConnectTimeout,
    ConnectionReset,
    RequestWriteTimeout,
    ResponseHeaderTimeout,
    PerTryTimeout,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Replay {
    pub mode: Storage,
    pub max_body_size_bytes: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    pub max_attempts: u8,
    pub methods: Vec<String>,
    pub idempotency_scope: Scope,
    pub per_try_timeout_ms: Option<u64>,
    pub total_timeout_ms: Option<u64>,
    pub retry_on: Vec<Cause>,
    pub replay: Replay,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Disabled,
            max_attempts: 1,
            methods: vec!["GET".into(), "HEAD".into(), "OPTIONS".into()],
            idempotency_scope: Scope::Endpoint,
            per_try_timeout_ms: None,
            total_timeout_ms: None,
            retry_on: vec![
                Cause::ConnectFailure,
                Cause::ConnectTimeout,
                Cause::ConnectionReset,
            ],
            replay: Replay::default(),
            backoff_base_ms: 100,
            backoff_max_ms: 1000,
        }
    }
}
impl Replay {
    pub fn cap(&self) -> u64 {
        self.max_body_size_bytes.unwrap_or(match self.mode {
            Storage::None => 0,
            Storage::Memory => 65536,
            Storage::Disk => 536870912,
        })
    }
}
impl Policy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if !(1..=5).contains(&self.max_attempts)
            || (self.mode == Mode::Disabled && self.max_attempts != 1)
            || self.methods.len() > 5
            || self
                .methods
                .iter()
                .any(|m| !["GET", "HEAD", "OPTIONS", "PUT", "DELETE"].contains(&m.as_str()))
            || self
                .methods
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.methods.len()
            || self.retry_on.len() > 6
            || self
                .retry_on
                .iter()
                .enumerate()
                .any(|(i, c)| self.retry_on[..i].contains(c))
            || self
                .per_try_timeout_ms
                .is_some_and(|v| !(1..=86400000).contains(&v))
            || self
                .total_timeout_ms
                .is_some_and(|v| !(1..=86400000).contains(&v))
            || self
                .per_try_timeout_ms
                .zip(self.total_timeout_ms)
                .is_some_and(|(a, b)| a > b)
            || self.backoff_base_ms > self.backoff_max_ms
            || self.backoff_max_ms > 30000
        {
            return Err(Validation::Retry);
        }
        match (self.replay.mode, self.replay.max_body_size_bytes) {
            (Storage::None, None) => {}
            (Storage::Memory | Storage::Disk, None)
            | (Storage::Memory, Some(1..=1048576))
            | (Storage::Disk, Some(1..=2147483648)) => {}
            _ => return Err(Validation::Retry),
        }
        Ok(())
    }
    pub fn authorized(
        &self,
        method: &str,
        valid_key: bool,
        sent: bool,
        complete: bool,
        body_empty: bool,
    ) -> bool {
        if self.mode == Mode::Disabled || (self.mode == Mode::Idempotent && !valid_key) {
            return false;
        }
        if self.mode == Mode::Safe && !self.methods.iter().any(|m| m == method) {
            return false;
        }
        if !sent {
            return true;
        }
        if !body_empty && (self.replay.mode == Storage::None || !complete) {
            return false;
        }
        match self.mode {
            Mode::Safe => self.methods.iter().any(|m| m == method),
            Mode::Idempotent => valid_key,
            _ => false,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Inspection {
    #[default]
    Full,
    HeadersQueryOnly,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Body {
    pub max_body_bytes: u64,
    pub inspection: Inspection,
    pub idle_timeout_ms: u64,
}
impl Default for Body {
    fn default() -> Self {
        Self {
            max_body_bytes: 65536,
            inspection: Inspection::Full,
            idle_timeout_ms: 30000,
        }
    }
}
impl Body {
    pub fn validate(&self) -> Result<(), Validation> {
        if !(1..=2147483648).contains(&self.max_body_bytes)
            || !(1..=120000).contains(&self.idle_timeout_ms)
        {
            return Err(Validation::Retry);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permission_is_not_replay() {
        let mut p = Policy {
            mode: Mode::ConnectOnly,
            max_attempts: 2,
            ..Default::default()
        };
        assert!(p.authorized("POST", false, false, false, false));
        assert!(!p.authorized("POST", false, true, true, false));
        p.mode = Mode::Safe;
        p.replay = Replay {
            mode: Storage::Memory,
            max_body_size_bytes: Some(65536),
        };
        assert!(!p.authorized("POST", true, true, true, false));
        assert!(!p.authorized("GET", false, true, false, false));
        assert!(p.authorized("GET", false, true, true, false));
        p.mode = Mode::Idempotent;
        assert!(!p.authorized("POST", false, false, true, false));
        assert!(p.authorized("POST", true, true, true, false));
    }
    #[test]
    fn reject_inconsistent_budgets() {
        let mut p = Policy {
            max_attempts: 2,
            ..Default::default()
        };
        assert!(p.validate().is_err());
        p.mode = Mode::Safe;
        assert!(p.validate().is_ok());
        p.replay.mode = Storage::Disk;
        assert!(p.validate().is_ok());
        p.replay.max_body_size_bytes = Some(536870912);
        assert!(p.validate().is_ok());
        p.total_timeout_ms = Some(100);
        p.per_try_timeout_ms = Some(101);
        assert!(p.validate().is_err());
    }
}
