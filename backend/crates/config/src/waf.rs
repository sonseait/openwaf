//! Declarative per-route WAF policy. Native compilation is a control-plane step.
use crate::Validation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Mode {
    Off,
    #[default]
    DetectionOnly,
    On,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    pub paranoia_level: u8,
    pub body_limit_bytes: usize,
    pub inspection_timeout_ms: u64,
    pub exclusions: Vec<Exclusion>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::DetectionOnly,
            paranoia_level: 1,
            body_limit_bytes: 65536,
            inspection_timeout_ms: 2000,
            exclusions: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub rule_id: u32,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}
impl Policy {
    pub fn validate(&mut self) -> Result<(), Validation> {
        if !(1..=4).contains(&self.paranoia_level)
            || !(1..=65536).contains(&self.body_limit_bytes)
            || !(1..=2000).contains(&self.inspection_timeout_ms)
            || self.exclusions.len() > 32
        {
            return Err(Validation::Waf);
        }
        let mut ids = BTreeSet::new();
        for exclusion in &self.exclusions {
            if exclusion.owner.as_ref().is_some_and(|v| {
                v.trim().is_empty() || v.len() > 128 || v.chars().any(char::is_control)
            }) || !(900000..=999999).contains(&exclusion.rule_id)
                || !ids.insert((exclusion.rule_id, exclusion.target.clone()))
                || exclusion.target.as_ref().is_some_and(|t| !valid_target(t))
                || exclusion
                    .expires_at_unix_ms
                    .is_some_and(|v| v == 0 || v > 253402300799999)
                || exclusion.reason.trim().is_empty()
                || exclusion.reason.len() > 256
                || exclusion.reason.chars().any(char::is_control)
            {
                return Err(Validation::Waf);
            }
        }
        self.exclusions.sort_by_key(|e| e.rule_id);
        Ok(())
    }
}

pub fn valid_target(value: &str) -> bool {
    let Some((collection, name)) = value.split_once(':') else {
        return false;
    };
    [
        "ARGS",
        "ARGS_GET",
        "ARGS_POST",
        "REQUEST_HEADERS",
        "REQUEST_COOKIES",
    ]
    .contains(&collection)
        && !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Counts offers while each exclusion was configured and unexpired. These are
/// exposure counts, not matches or estimates of requests needing the exception.
/// No payload/matched data, bounded to 32 exclusions per route/config generation.
pub struct Usage {
    offered: std::sync::atomic::AtomicU64,
    exclusions: Vec<std::sync::atomic::AtomicU64>,
}
impl Usage {
    pub fn new(policy: Option<&Policy>) -> Self {
        Self {
            offered: Default::default(),
            exclusions: (0..policy.map_or(0, |p| p.exclusions.len()))
                .map(|_| Default::default())
                .collect(),
        }
    }
    pub fn record(&self, policy: Option<&Policy>, now: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.offered.fetch_add(1, Relaxed);
        if let Some(policy) = policy {
            for (i, e) in policy.exclusions.iter().enumerate() {
                if e.expires_at_unix_ms.is_none_or(|v| v > now)
                    && let Some(count) = self.exclusions.get(i)
                {
                    count.fetch_add(1, Relaxed);
                }
            }
        }
    }
    pub fn summary(&self, policy: &Policy, now: u64) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        serde_json::json!({"inspection_offers":self.offered.load(Relaxed),"usage_kind":"offered_while_active_not_rule_matches","exclusions":policy.exclusions.iter().enumerate().map(|(i,e)|serde_json::json!({"rule_id":e.rule_id,"target":e.target,"owner":e.owner,"reason":e.reason,"expires_at_unix_ms":e.expires_at_unix_ms,"state":match e.expires_at_unix_ms {Some(v) if v<=now=>"expired",Some(v) if v<=now.saturating_add(86400000)=>"expiring_soon",Some(_)=>"active",None=>"no_expiry"},"offered_while_active":self.exclusions.get(i).map_or(0,|n|n.load(Relaxed))})).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_usage_denominator_expiry_owner_and_legacy_metadata() {
        let mut policy: Policy=serde_json::from_value(serde_json::json!({"exclusions":[{"rule_id":941100,"reason":"Legacy exception"},{"rule_id":942100,"reason":"Time bounded","owner":"Security","expires_at_unix_ms":200}]})).unwrap();
        policy.validate().unwrap();
        let usage = Usage::new(Some(&policy));
        usage.record(Some(&policy), 100);
        usage.record(Some(&policy), 300);
        let report = usage.summary(&policy, 300);
        assert_eq!(report["inspection_offers"], 2);
        assert_eq!(report["exclusions"][0]["offered_while_active"], 2);
        assert_eq!(report["exclusions"][1]["offered_while_active"], 1);
        assert_eq!(report["exclusions"][1]["state"], "expired");
        policy.exclusions[0].owner = Some(" ".into());
        assert!(policy.validate().is_err());
        policy.exclusions[0].owner = None;
        policy.exclusions[0].expires_at_unix_ms = Some(0);
        assert!(policy.validate().is_err());
    }
}
