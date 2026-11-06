//! Pure route access-policy validation. ACL allow never skips later layers.
use crate::{Validation, normalized_ip};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
    pub geo: Option<Geo>,
    pub rate_limit: Option<RateLimit>,
    /// Aggregate HTTP flood budget shared by every client in this scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ddos: Option<RateLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<Challenge>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Geo {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    pub unknown: Unknown,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unknown {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub per_second: u32,
    pub burst: u32,
}
/// Opt-in browser proof-of-work; both global and route scopes must pass.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub difficulty: u8,
    pub clearance_seconds: u32,
}
impl Challenge {
    pub fn validate(&self) -> Result<(), Validation> {
        if !(8..=20).contains(&self.difficulty) || !(60..=86400).contains(&self.clearance_seconds) {
            return Err(Validation::Access);
        }
        Ok(())
    }
}
impl Policy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if let Some(challenge) = self.challenge {
            challenge.validate()?;
        }
        for list in [&self.allow, &self.deny] {
            if list.len() > 128
                || list.iter().map(IpNet::trunc).collect::<BTreeSet<_>>().len() != list.len()
            {
                return Err(Validation::Access);
            }
            // Mapped IPv6 CIDRs are ambiguous after client-IP normalization.
            if list
                .iter()
                .any(|net| matches!(net, IpNet::V6(v6) if v6.addr().to_ipv4_mapped().is_some()))
            {
                return Err(Validation::Access);
            }
        }
        if let Some(geo) = &self.geo {
            for list in [&geo.allow, &geo.deny] {
                if list.len() > 249
                    || list.iter().collect::<BTreeSet<_>>().len() != list.len()
                    || list
                        .iter()
                        .any(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()))
                {
                    return Err(Validation::Access);
                }
            }
        }
        for limit in [self.rate_limit, self.ddos].into_iter().flatten() {
            if !(1..=10000).contains(&limit.per_second) || !(1..=10000).contains(&limit.burst) {
                return Err(Validation::Access);
            }
        }
        Ok(())
    }
    pub fn permits_ip(&self, ip: IpAddr) -> bool {
        let ip = normalized_ip(ip);
        !self.deny.iter().any(|net| net.contains(&ip))
            && (self.allow.is_empty() || self.allow.iter().any(|net| net.contains(&ip)))
    }
}
impl Geo {
    pub fn permits(&self, country: Option<&str>) -> bool {
        let Some(country) = country else {
            return self.unknown == Unknown::Allow;
        };
        !self.deny.iter().any(|c| c == country)
            && (self.allow.is_empty() || self.allow.iter().any(|c| c == country))
    }
}
