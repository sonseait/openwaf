//! Advisory discovery provenance, persisted with the explicitly chosen endpoint.
use crate::{Address, Validation, hostname};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    DockerAlias {
        container_id: String,
        network: String,
        alias: String,
        port: u16,
        observed_at_unix_ms: u64,
    },
    DockerPublished {
        container_id: String,
        bind_address: IpAddr,
        container_port: u16,
        host_port: u16,
        observed_at_unix_ms: u64,
    },
    HostPort {
        bind_address: IpAddr,
        port: u16,
        observed_at_unix_ms: u64,
    },
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
impl Source {
    pub fn validate(&self, address: &Address) -> Result<(), Validation> {
        let valid = match self {
            Self::DockerAlias {
                container_id,
                network,
                alias,
                port,
                observed_at_unix_ms,
            } => {
                identifier(container_id)
                    && identifier(network)
                    && hostname(alias).is_ok_and(|name| name == *alias && name == address.host())
                    && alias.parse::<IpAddr>().is_err()
                    && *port == address.port()
                    && *observed_at_unix_ms > 0
            }
            Self::DockerPublished {
                container_id,
                container_port,
                host_port,
                observed_at_unix_ms,
                ..
            } => {
                identifier(container_id)
                    && *container_port > 0
                    && *host_port == address.port()
                    && *observed_at_unix_ms > 0
            }
            Self::HostPort {
                port,
                observed_at_unix_ms,
                ..
            } => *port == address.port() && *observed_at_unix_ms > 0,
        };
        if valid {
            Ok(())
        } else {
            Err(Validation::Endpoint)
        }
    }
}
