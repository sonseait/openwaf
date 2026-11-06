//! Linux network namespace inventory, never a port scan and never PID-dependent.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::io::AsyncReadExt;
const MAX_PROC_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LISTENERS: usize = 16_384;
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct Listener {
    pub bind_address: IpAddr,
    pub port: u16,
}
fn parse(input: &str, ipv6: bool) -> Result<Vec<Listener>> {
    let mut found = BTreeSet::new();
    for line in input.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() >= 4, "invalid Linux TCP table row");
        if fields[3] != "0A" {
            continue;
        }
        let (address, port) = fields[1]
            .split_once(':')
            .context("invalid listener address")?;
        ensure!(
            address.len() == if ipv6 { 32 } else { 8 },
            "invalid address width"
        );
        let ip = if ipv6 {
            let mut bytes = [0; 16];
            for (index, word) in address.as_bytes().as_chunks::<8>().0.iter().enumerate() {
                let word = std::str::from_utf8(word)?;
                bytes[index * 4..index * 4 + 4]
                    .copy_from_slice(&u32::from_str_radix(word, 16)?.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                u32::from_str_radix(address, 16)?.to_ne_bytes(),
            ))
        };
        found.insert(Listener {
            bind_address: ip,
            port: u16::from_str_radix(port, 16)?,
        });
        ensure!(found.len() <= MAX_LISTENERS, "too many TCP listeners");
    }
    Ok(found.into_iter().collect())
}
async fn table(path: &str, optional: bool) -> Result<String> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(String::new());
        }
        Err(_) => anyhow::bail!("cannot read Linux TCP table"),
    };
    let mut data = String::new();
    file.take(MAX_PROC_BYTES + 1)
        .read_to_string(&mut data)
        .await
        .context("read Linux TCP table")?;
    ensure!(
        data.len() as u64 <= MAX_PROC_BYTES,
        "Linux TCP table exceeds limit"
    );
    Ok(data)
}
pub async fn collect(excluded: &[SocketAddr]) -> Result<Vec<Listener>> {
    ensure!(cfg!(target_os = "linux"), "host discovery requires Linux");
    let (v4, v6) = tokio::try_join!(table("/proc/net/tcp", false), table("/proc/net/tcp6", true))?;
    let mut listeners = BTreeSet::new();
    for listener in parse(&v4, false)?.into_iter().chain(parse(&v6, true)?) {
        if !excluded.iter().any(|endpoint| {
            endpoint.port() == listener.port && endpoint.ip() == listener.bind_address
        }) {
            listeners.insert(listener);
        }
    }
    ensure!(listeners.len() <= MAX_LISTENERS, "too many TCP listeners");
    Ok(listeners.into_iter().collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(target_endian = "little")]
    fn ipv4_ipv6_listener_only_and_dedup() {
        let input = "header\n0: 0100007F:1F90 00000000:0000 0A\n1: 0100007F:1F90 00000000:0000 0A\n2: 00000000:0050 00000000:0000 01\n";
        let found = parse(input, false).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bind_address.to_string(), "127.0.0.1");
        assert_eq!(found[0].port, 8080);
        let found = parse(
            "header\n0: 00000000000000000000000001000000:01BB 0:0 0A",
            true,
        )
        .unwrap();
        assert_eq!(found[0].bind_address.to_string(), "::1");
        assert_eq!(found[0].port, 443);
    }
    #[test]
    fn malformed_table_is_not_partial_success() {
        assert!(parse("header\ninvalid", false).is_err());
        assert!(parse("header\n0: BAD:GG 0:0 0A", false).is_err());
    }
}
