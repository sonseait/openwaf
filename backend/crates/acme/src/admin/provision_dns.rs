//! One-time, bounded DNS reconciliation with durable intents for ambiguous writes.
use super::*;

fn targets(settings: &Settings, zone: &Zone) -> Vec<Value> {
    let mut targets = Vec::new();
    let record = |name: &str, kind: &str, content: String| json!({"name":name,"type":kind,"content":content,"proxied":settings.proxied,"ttl":1,"comment":format!("openwaf-admin-bootstrap:{}",settings.hostname)});
    if let Some(ip) = settings.ipv4 {
        targets.push(record(&zone.name, "A", ip.to_string()));
    }
    if let Some(ip) = settings.ipv6 {
        targets.push(record(&zone.name, "AAAA", ip.to_string()));
    }
    targets.push(record(
        &format!("*.{}", zone.name),
        "CNAME",
        zone.name.clone(),
    ));
    if settings.hostname != zone.name {
        targets.push(record(&settings.hostname, "CNAME", zone.name.clone()));
    }
    targets
}
fn matches(row: &Value, target: &Value) -> bool {
    ["name", "type", "content", "proxied", "ttl", "comment"]
        .iter()
        .all(|key| row[key] == target[key])
}
fn validate_rows(name: &str, zone: &Zone, rows: &[Value], cname: bool) -> Result<()> {
    ensure!(
        rows.iter().all(|row| row["name"] == name
            && row["id"].as_str().is_some_and(openwaf_cloudflare::valid_id)),
        "invalid DNS inventory"
    );
    ensure!(
        !rows
            .iter()
            .any(|row| (name != zone.name && row["type"] == "NS")
                || (cname
                    && !["A", "AAAA", "CNAME"]
                        .iter()
                        .any(|kind| row["type"] == *kind))),
        "unrelated DNS records prevent bootstrap CNAME; reconcile manually"
    );
    Ok(())
}
async fn reconcile(root: &Path, client: &Client, zone: &Zone, pending: &Path) -> Result<()> {
    if !pending.try_exists()? {
        return Ok(());
    }
    let intent: Value = serde_json::from_slice(&files::read(pending, 8192, true)?)?;
    // Reconcile legacy v1 POST/PATCH intent before migrating DNS layout.
    let target = intent.get("target").unwrap_or(&intent);
    let name = target["name"]
        .as_str()
        .context("invalid pending DNS owner")?;
    ensure!(
        name == zone.name || name.ends_with(&format!(".{}", zone.name)),
        "pending DNS owner outside zone"
    );
    let rows = records(client, zone, name).await?;
    let confirmed = if intent["method"] == "DELETE" {
        !rows.iter().any(|row| row["id"] == target["id"])
    } else {
        rows.iter().any(|row| matches(row, target))
    };
    ensure!(
        confirmed,
        "DNS write outcome unknown; pending intent retained, do not blindly repeat write"
    );
    files::replace_secret(
        &root.join("dns-v2-last-operation.json"),
        &serde_json::to_vec(&json!({"result":"confirmed","method":intent["method"],"name":name}))?,
    )?;
    std::fs::remove_file(pending)?;
    files::sync_dir(root)
}
async fn write(
    root: &Path,
    client: &Client,
    zone: &Zone,
    method: Method,
    target: &Value,
    id: Option<&str>,
) -> Result<()> {
    let pending = root.join("dns-pending.json");
    let path = format!(
        "/zones/{}/dns_records{}",
        zone.id,
        id.map(|id| format!("/{id}")).unwrap_or_default()
    );
    files::write_new(
        &pending,
        &serde_json::to_vec(&json!({"method":method.as_str(),"target":target}))?,
    )?;
    files::sync_dir(root)?;
    let payload = (method != Method::DELETE).then_some(target);
    if let Err(code) = client.call(method, &path, &[], payload).await {
        if !matches!(code, ApiError::OutcomeUnknown | ApiError::Unavailable) {
            std::fs::remove_file(&pending)?;
            files::sync_dir(root)?;
        }
        anyhow::bail!("bootstrap DNS write: {code:?}");
    }
    reconcile(root, client, zone, &pending).await
}
pub(super) async fn run(
    root: &Path,
    settings: &Settings,
    client: &Client,
    zone: &Zone,
) -> Result<()> {
    validate_zone(settings, zone)?;
    let checkpoint = json!({"version":2,"zone_id":zone.id,"zone_name":zone.name,"hostname":settings.hostname,"ipv4":settings.ipv4,"ipv6":settings.ipv6});
    let complete = root.join("dns-v2-complete.json");
    if complete.try_exists()? {
        ensure!(
            serde_json::from_slice::<Value>(&files::read(&complete, 4096, true)?)? == checkpoint,
            "bootstrap DNS checkpoint mismatch"
        );
        return Ok(());
    }
    reconcile(root, client, zone, &root.join("dns-pending.json")).await?;
    let targets = targets(settings, zone);
    let names: std::collections::BTreeSet<_> = targets
        .iter()
        .filter_map(|target| target["name"].as_str())
        .collect();
    // Validate every affected owner before the first destructive change.
    for name in &names {
        let rows = records(client, zone, name).await?;
        validate_rows(name, zone, &rows, *name != zone.name)?;
    }
    for name in &names {
        let name = *name;
        let rows = records(client, zone, name).await?;
        validate_rows(name, zone, &rows, name != zone.name)?;
        let wanted: Vec<_> = targets
            .iter()
            .filter(|target| target["name"] == name)
            .collect();
        let mut retained = std::collections::BTreeSet::new();
        for row in rows {
            if !["A", "AAAA", "CNAME"]
                .iter()
                .any(|kind| row["type"] == *kind)
            {
                continue;
            }
            let kind = row["type"].as_str().context("invalid DNS type")?;
            let keep = wanted.iter().any(|target| target["type"] == kind)
                && retained.insert(kind.to_owned());
            let id = row["id"].as_str().context("invalid DNS ID")?;
            let current = records(client, zone, name).await?;
            ensure!(
                current.contains(&row),
                "DNS record changed concurrently; retry reconciliation"
            );
            if !keep {
                write(root, client, zone, Method::DELETE, &row, Some(id)).await?;
            }
        }
        for target in wanted {
            let rows = records(client, zone, name).await?;
            let existing = rows.iter().find(|row| row["type"] == target["type"]);
            if existing.is_some_and(|row| matches(row, target)) {
                continue;
            }
            let id = existing.and_then(|row| row["id"].as_str());
            write(
                root,
                client,
                zone,
                if id.is_some() {
                    Method::PATCH
                } else {
                    Method::POST
                },
                target,
                id,
            )
            .await?;
        }
    }
    // A final bounded read prevents declaring a partially reconciled layout complete.
    for name in &names {
        let rows = records(client, zone, name).await?;
        validate_rows(name, zone, &rows, *name != zone.name)?;
        let wanted: Vec<_> = targets
            .iter()
            .filter(|target| target["name"] == *name)
            .collect();
        let addresses: Vec<_> = rows
            .iter()
            .filter(|row| {
                ["A", "AAAA", "CNAME"]
                    .iter()
                    .any(|kind| row["type"] == *kind)
            })
            .collect();
        ensure!(
            addresses.len() == wanted.len()
                && wanted
                    .iter()
                    .all(|target| addresses.iter().any(|row| matches(row, target))),
            "DNS layout changed during reconciliation; checkpoint not committed"
        );
    }
    files::write_new(&complete, &serde_json::to_vec(&checkpoint)?)?;
    files::sync_dir(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unrelated_cname_conflicts_and_allows_apex_mail() -> Result<()> {
        let zone = Zone {
            id: "a".repeat(32),
            name: "example.com".into(),
        };
        let rows = vec![json!({"id":"b".repeat(32),"name":"example.com","type":"MX"})];
        validate_rows("example.com", &zone, &rows, false)?;
        let rows = vec![json!({"id":"b".repeat(32),"name":"admin.example.com","type":"TXT"})];
        assert!(validate_rows("admin.example.com", &zone, &rows, true).is_err());
        Ok(())
    }
}
