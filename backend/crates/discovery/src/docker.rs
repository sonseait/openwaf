//! Only two read-only Docker methods; no forwarding of arbitrary Docker requests.
use anyhow::{Context, Result, ensure};
use bollard::{
    API_DEFAULT_VERSION, Docker,
    query_parameters::{InspectContainerOptions, ListContainersOptionsBuilder},
};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
const MAX_CONTAINERS: usize = 512;
#[derive(Clone, Debug, Serialize)]
pub struct Network {
    pub name: String,
    pub aliases: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PublishedPort {
    pub container_port: u16,
    pub protocol: String,
    pub bind_address: String,
    pub host_port: u16,
}
#[derive(Clone, Debug, Serialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub health: Option<String>,
    pub compose_service: Option<String>,
    pub compose_project: Option<String>,
    pub networks: Vec<Network>,
    pub exposed_ports: Vec<String>,
    pub published_ports: Vec<PublishedPort>,
    pub unavailable_reason: Option<&'static str>,
}
fn text(value: &Value) -> Result<String> {
    let value = value.as_str().context("invalid Docker metadata string")?;
    ensure!(value.len() <= 1024, "Docker metadata string too long");
    Ok(value.into())
}
fn optional(value: &Value) -> Result<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        text(value).map(Some)
    }
}
fn map(value: &Value) -> Result<BTreeMap<String, Value>> {
    if value.is_null() {
        return Ok(BTreeMap::new());
    }
    let map = value.as_object().context("invalid Docker metadata map")?;
    ensure!(map.len() <= 128, "too much Docker metadata");
    map.iter()
        .map(|(key, value)| {
            ensure!(key.len() <= 1024, "Docker metadata key too long");
            Ok((key.clone(), value.clone()))
        })
        .collect()
}
fn port(value: &str) -> Result<(u16, String)> {
    let (number, protocol) = value.split_once('/').context("invalid Docker port")?;
    ensure!(
        matches!(protocol, "tcp" | "udp" | "sctp"),
        "invalid Docker protocol"
    );
    Ok((
        number.parse().context("invalid Docker port number")?,
        protocol.into(),
    ))
}
fn project(value: Value) -> Result<Container> {
    let config = &value["Config"];
    let state = &value["State"];
    let networks = map(&value["NetworkSettings"]["Networks"])?
        .into_iter()
        .map(|(name, network)| {
            let aliases = match &network["Aliases"] {
                Value::Null => Vec::new(),
                Value::Array(values) => {
                    ensure!(values.len() <= 128, "too many Docker aliases");
                    values.iter().map(text).collect::<Result<Vec<_>>>()?
                }
                _ => anyhow::bail!("invalid Docker aliases"),
            };
            Ok(Network { name, aliases })
        })
        .collect::<Result<Vec<_>>>()?;
    let exposed_ports = map(&config["ExposedPorts"])?
        .into_keys()
        .map(|value| {
            port(&value)?;
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut published_ports = Vec::new();
    for (key, bindings) in map(&value["NetworkSettings"]["Ports"])? {
        let (container_port, protocol) = port(&key)?;
        if bindings.is_null() {
            continue;
        }
        let bindings = bindings.as_array().context("invalid Docker bindings")?;
        ensure!(bindings.len() <= 128, "too many Docker bindings");
        for binding in bindings {
            published_ports.push(PublishedPort {
                container_port,
                protocol: protocol.clone(),
                bind_address: text(&binding["HostIp"])?,
                host_port: text(&binding["HostPort"])?
                    .parse()
                    .context("invalid published port")?,
            });
            ensure!(published_ports.len() <= 512, "too many published ports");
        }
    }
    let status = text(&state["Status"])?;
    Ok(Container {
        id: text(&value["Id"])?,
        name: text(&value["Name"])?.trim_start_matches('/').into(),
        image: text(&config["Image"])?,
        unavailable_reason: if status == "running" {
            None
        } else {
            Some("container_not_running")
        },
        state: status,
        health: optional(&state["Health"]["Status"])?,
        compose_service: optional(&config["Labels"]["com.docker.compose.service"])?,
        compose_project: optional(&config["Labels"]["com.docker.compose.project"])?,
        networks,
        exposed_ports,
        published_ports,
    })
}
pub fn validate_socket_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "Docker socket must be an absolute local path"
    );
    ensure!(path.to_str().is_some(), "invalid Docker socket path");
    Ok(())
}
fn client(path: &Path) -> Result<Docker> {
    ensure!(
        path.is_absolute(),
        "Docker socket must be an absolute local path"
    );
    Docker::connect_with_unix(
        path.to_str().context("invalid Docker socket path")?,
        2,
        API_DEFAULT_VERSION,
    )
    .context("configure local Docker client")
}
pub async fn collect(path: &Path) -> Result<Vec<Container>> {
    validate_socket_path(path)?;
    // Never use Docker environment variables, remote transports or caller paths.
    let proxy = crate::transport::BoundedSocket::start(path)?;
    let docker = client(&proxy.path())?
        .negotiate_version()
        .await
        .context("Docker API negotiation failed")?;
    let list = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::default().all(true).build(),
        ))
        .await
        .context("Docker inventory failed")?;
    ensure!(list.len() <= MAX_CONTAINERS, "too many Docker containers");
    let mut result = Vec::new();
    let mut projected_bytes = 0;
    for container in list {
        let id = container.id.context("Docker ID missing")?;
        let inspect = docker
            .inspect_container(&id, None::<InspectContainerOptions>)
            .await
            .context("Docker inspect failed")?;
        let projected = project(serde_json::to_value(inspect)?)?;
        let bytes = crate::state::encode(&projected)?.len();
        ensure!(
            bytes <= 128 * 1024,
            "Docker container metadata exceeds limit"
        );
        projected_bytes += bytes;
        ensure!(
            projected_bytes <= 3 * 1024 * 1024,
            "Docker inventory metadata exceeds limit"
        );
        result.push(projected);
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::json!({"Id":"id","Name":"/app","Config":{"Image":"app:tag","Labels":{"com.docker.compose.service":"web"},"ExposedPorts":{"80/tcp":{},"53/udp":{}}},"State":{"Status":"exited"},"NetworkSettings":{"Networks":{"b":{"Aliases":["web"]},"a":{"Aliases":["app"]}},"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}]}}})
    }
    #[test]
    fn projects_all_networks_ports_without_guessing_endpoint() {
        let container = project(fixture()).unwrap();
        assert_eq!(container.networks.len(), 2);
        assert_eq!(container.published_ports.len(), 2);
        assert_eq!(container.published_ports[0].bind_address, "0.0.0.0");
        assert_eq!(container.exposed_ports.len(), 2);
        assert_eq!(container.unavailable_reason, Some("container_not_running"));
        assert_eq!(container.compose_service.as_deref(), Some("web"));
    }
    #[test]
    fn rejects_bad_metadata_and_remote_socket() {
        let mut data = fixture();
        data["NetworkSettings"]["Ports"]["80/tcp"][0]["HostPort"] = serde_json::json!("bad");
        assert!(project(data).is_err());
        assert!(client(Path::new("tcp://host:2375")).is_err());
    }
}
