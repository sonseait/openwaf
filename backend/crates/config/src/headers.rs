use crate::{Validation, normalized_ip};
use ipnet::IpNet;
use std::net::IpAddr;

pub fn client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &[IpNet],
) -> Result<IpAddr, Validation> {
    let mut current = normalized_ip(peer);
    if !trusted.iter().any(|net| net.contains(&current)) {
        return Ok(current);
    }
    let Some(value) = forwarded_for else {
        return Ok(current);
    };
    let parts: Vec<_> = value.split(',').collect();
    if parts.len() > 16 || value.len() > 1024 {
        return Err(Validation::Limit);
    }
    // Validate the complete list even if an untrusted hop would stop traversal.
    let parts = parts
        .iter()
        .map(|part| {
            part.trim()
                .parse::<IpAddr>()
                .map(normalized_ip)
                .map_err(|_| Validation::Endpoint)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for candidate in parts.into_iter().rev() {
        if !trusted.iter().any(|net| net.contains(&current)) {
            break;
        }
        current = candidate;
    }
    Ok(current)
}
