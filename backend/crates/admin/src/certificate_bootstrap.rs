//! Startup-only provider import and renewal ownership reservation. No listener.
use crate::*;
use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema_version: u32,
    hostname: String,
    zone_id: String,
    zone_name: String,
}
impl Descriptor {
    fn validate(&self, hostname: &str) -> Result<()> {
        let child = self.hostname.strip_suffix(&format!(".{}", self.zone_name));
        ensure!(
            self.schema_version == 2
                && self.hostname == hostname
                && openwaf_cloudflare::valid_id(&self.zone_id)
                && openwaf_config::hostname(&self.zone_name)? == self.zone_name
                && self.zone_name.contains('.')
                && !self.zone_name.starts_with("*.")
                && self.zone_name.parse::<std::net::IpAddr>().is_err()
                && (self.hostname == self.zone_name
                    || child.is_some_and(|label| !label.is_empty() && !label.contains('.'))),
            "invalid bootstrap zone descriptor"
        );
        Ok(())
    }
    fn names(&self) -> Vec<String> {
        let mut names = vec![
            self.zone_name.clone(),
            format!("*.{}", self.zone_name),
            self.hostname.clone(),
        ];
        names.sort();
        names.dedup();
        names
    }
}
pub(crate) async fn reserved(
    db: &PgPool,
    hostname: &str,
) -> std::result::Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM bootstrap_certificate_ownership WHERE hostname=$1)",
    )
    .bind(hostname)
    .fetch_one(db)
    .await
}
async fn import(db: &PgPool, key: &MasterKey, root: &Path, descriptor: &Descriptor) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query(
        "SELECT hostname,zone_id,zone_name FROM bootstrap_certificate_import WHERE singleton=true",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        ensure!(
            row.try_get::<String, _>("hostname")? == descriptor.hostname
                && row.try_get::<String, _>("zone_id")? == descriptor.zone_id
                && row.try_get::<String, _>("zone_name")? == descriptor.zone_name,
            "bootstrap import identity changed"
        );
        tx.commit().await?;
        return Ok(());
    }
    let names = descriptor.names();
    let conflict: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM certificate_requests WHERE hostname=ANY($1)) OR EXISTS(SELECT 1 FROM application_certificates WHERE hostname=ANY($1) AND state<>'covered')")
        .bind(&names).fetch_one(&mut *tx).await?;
    ensure!(
        !conflict,
        "bootstrap certificate has another queue owner; migration not applied"
    );
    let existing: Vec<String> = sqlx::query_scalar("SELECT id FROM certificate_providers WHERE zone_id=$1 AND zone_name=$2 AND environment='production' ORDER BY id LIMIT 17")
        .bind(&descriptor.zone_id).bind(&descriptor.zone_name).fetch_all(&mut *tx).await?;
    ensure!(existing.len() <= 16, "provider inventory exceeds limit");
    let id = if let Some(id) = existing.first() {
        id.clone()
    } else {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certificate_providers")
            .fetch_one(&mut *tx)
            .await?;
        ensure!(count < 16, "provider capacity prevents bootstrap import");
        let encrypted = crypto::private_file(&root.join("credential.enc"), 2081)?;
        let plain = key.open(
            &format!("bootstrap-cloudflare:{}", descriptor.hostname),
            &encrypted,
        )?;
        let credentials: openwaf_cloudflare::Credentials = serde_json::from_slice(&plain)
            .map_err(|_| anyhow::anyhow!("invalid bootstrap credential"))?;
        credentials.validate()?;
        let id = format!("bootstrap-{}", descriptor.zone_id.to_ascii_lowercase());
        let encrypted = key.seal(&format!("cloudflare-provider:{id}"), &plain)?;
        ensure!(sqlx::query("INSERT INTO certificate_providers(id,name,zone_id,zone_name,environment,credential) VALUES($1,$2,$3,$4,'production',$5)")
            .bind(&id).bind(format!("Cloudflare {} (Production)",descriptor.zone_name.chars().take(76).collect::<String>())).bind(&descriptor.zone_id).bind(&descriptor.zone_name).bind(encrypted).execute(&mut *tx).await?.rows_affected()==1,"bootstrap provider insert failed");
        id
    };
    for name in names {
        ensure!(sqlx::query("INSERT INTO bootstrap_certificate_ownership(hostname,owner) VALUES($1,'admin-bootstrap')").bind(name).execute(&mut *tx).await?.rows_affected()==1,"bootstrap ownership conflict");
    }
    ensure!(sqlx::query("INSERT INTO bootstrap_certificate_import(schema_version,hostname,zone_id,zone_name,provider_id) VALUES(2,$1,$2,$3,$4)").bind(&descriptor.hostname).bind(&descriptor.zone_id).bind(&descriptor.zone_name).bind(&id).execute(&mut *tx).await?.rows_affected()==1,"bootstrap import marker failed");
    audit(
        &mut tx,
        None,
        "certificate_provider.bootstrap_import",
        &id,
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
/// Called by the one-shot Compose preflight before bootstrap writes public DNS.
pub async fn provision() -> Result<()> {
    let root = PathBuf::from(
        std::env::var_os("OPENWAF_BOOTSTRAP_PROVIDER_ROOT")
            .context("bootstrap handoff required")?,
    );
    ensure!(root.is_absolute(), "absolute bootstrap handoff required");
    let host = crate::bootstrap::public_host()?.context("public admin hostname required")?;
    let key = MasterKey::load(Path::new(&std::env::var("OPENWAF_ADMIN_MASTER_KEY_FILE")?))?;
    let db = crate::connect(&std::env::var("OPENWAF_DATABASE_URL")?).await?;
    crate::validate_key(&db, &key).await?;
    let operation = async {
        let descriptor = loop {
            let path = root.join("zone.json");
            if path.try_exists()? {
                let bytes = crypto::private_file(&path, 4096)?;
                let descriptor: Descriptor = serde_json::from_slice(&bytes)?;
                descriptor.validate(&host)?;
                break descriptor;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        import(&db, &key, &root, &descriptor).await?;
        let output = root.join("reserved.json");
        let bytes = serde_json::to_vec(&descriptor)?;
        if output.try_exists()? {
            ensure!(
                crypto::private_file(&output, 4096)?.as_slice() == bytes,
                "bootstrap reservation changed"
            );
        } else {
            let temp = root.join(format!(".reservation-{}", crypto::random_token()?));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, &output)?;
            std::fs::File::open(&root)?.sync_all()?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::time::timeout(Duration::from_secs(900), operation)
        .await
        .context("bootstrap preflight deadline")?;
    db.close().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires a fresh isolated PostgreSQL database via OPENWAF_BOOTSTRAP_TEST_DATABASE_URL"]
    async fn postgres_import_is_atomic_idempotent_and_preserves_provider_changes() -> Result<()> {
        let db = connect(&std::env::var("OPENWAF_BOOTSTRAP_TEST_DATABASE_URL")?).await?;
        ensure!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM certificate_providers")
                .fetch_one(&db)
                .await?
                == 0,
            "test requires empty provider database"
        );
        let root = tempfile::tempdir()?;
        let mut random = [0; 32];
        openssl::rand::rand_bytes(&mut random)?;
        let key_path = root.path().join("key");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)?;
        file.write_all(&random)?;
        let key = MasterKey::load(&key_path)?;
        let descriptor = Descriptor {
            schema_version: 2,
            hostname: "admin.example.com".into(),
            zone_id: "a".repeat(32),
            zone_name: "example.com".into(),
        };
        let credentials = openwaf_cloudflare::Credentials {
            auth_type: "api_token".into(),
            secret: crypto::hex(&random),
            email: None,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&credentials)?);
        let encrypted = key.seal("bootstrap-cloudflare:admin.example.com", &plain)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("credential.enc"))?
            .write_all(&encrypted)?;
        // A queued job prevents both provider creation and renewal takeover.
        sqlx::query("INSERT INTO application_certificates(hostname) VALUES('example.com')")
            .execute(&db)
            .await?;
        assert!(import(&db, &key, root.path(), &descriptor).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM certificate_providers")
                .fetch_one(&db)
                .await?,
            0
        );
        sqlx::query("DELETE FROM application_certificates WHERE hostname='example.com'")
            .execute(&db)
            .await?;
        // Capacity failure is atomic too.
        let mut capacity_ids = Vec::new();
        for index in 0..16 {
            let id = format!("capacity-{index}");
            let envelope = key.seal(&format!("cloudflare-provider:{id}"), &plain)?;
            sqlx::query("INSERT INTO certificate_providers(id,name,zone_id,zone_name,environment,credential) VALUES($1,'capacity fixture',$2,'other.example.com','production',$3)").bind(&id).bind("b".repeat(32)).bind(envelope).execute(&db).await?;
            capacity_ids.push(id);
        }
        assert!(import(&db, &key, root.path(), &descriptor).await.is_err());
        assert!(!reserved(&db, "example.com").await?);
        sqlx::query("DELETE FROM certificate_providers WHERE id=ANY($1)")
            .bind(&capacity_ids)
            .execute(&db)
            .await?;
        // Audit failure rolls back provider, reservations and completion marker.
        sqlx::query("CREATE FUNCTION reject_bootstrap_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit rejection'; END $$").execute(&db).await?;
        sqlx::query("CREATE TRIGGER reject_bootstrap_audit BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION reject_bootstrap_audit()").execute(&db).await?;
        assert!(import(&db, &key, root.path(), &descriptor).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM certificate_providers")
                .fetch_one(&db)
                .await?,
            0
        );
        assert!(!reserved(&db, "example.com").await?);
        sqlx::query("DROP TRIGGER reject_bootstrap_audit ON admin_audit")
            .execute(&db)
            .await?;
        sqlx::query("DROP FUNCTION reject_bootstrap_audit()")
            .execute(&db)
            .await?;
        import(&db, &key, root.path(), &descriptor).await?;
        import(&db, &key, root.path(), &descriptor).await?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM certificate_providers")
                .fetch_one(&db)
                .await?,
            1
        );
        for name in descriptor.names() {
            assert!(reserved(&db, &name).await?);
        }
        let row = sqlx::query("SELECT id,credential FROM certificate_providers")
            .fetch_one(&db)
            .await?;
        let id: String = row.try_get("id")?;
        let envelope: Vec<u8> = row.try_get("credential")?;
        assert_eq!(
            key.open(&format!("cloudflare-provider:{id}"), &envelope)?
                .as_slice(),
            plain.as_slice()
        );
        assert!(
            !envelope
                .windows(credentials.secret.len())
                .any(|part| part == credentials.secret.as_bytes())
        );
        sqlx::query("UPDATE certificate_providers SET name='edited provider' WHERE id=$1")
            .bind(&id)
            .execute(&db)
            .await?;
        std::fs::remove_file(root.path().join("credential.enc"))?;
        import(&db, &key, root.path(), &descriptor).await?;
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT name FROM certificate_providers")
                .fetch_one(&db)
                .await?,
            "edited provider"
        );
        sqlx::query("DELETE FROM certificate_providers WHERE id=$1")
            .bind(&id)
            .execute(&db)
            .await?;
        import(&db, &key, root.path(), &descriptor).await?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM certificate_providers")
                .fetch_one(&db)
                .await?,
            0
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM admin_audit WHERE action='certificate_provider.bootstrap_import'").fetch_one(&db).await?,1);
        let changed = Descriptor {
            schema_version: 2,
            hostname: "other.example.com".into(),
            zone_id: descriptor.zone_id.clone(),
            zone_name: descriptor.zone_name.clone(),
        };
        assert!(import(&db, &key, root.path(), &changed).await.is_err());
        // Existing same-zone provider wins without reading or overwriting seed credentials.
        sqlx::query("DELETE FROM bootstrap_certificate_import")
            .execute(&db)
            .await?;
        sqlx::query("DELETE FROM bootstrap_certificate_ownership")
            .execute(&db)
            .await?;
        let keep = key.seal("cloudflare-provider:existing", &plain)?;
        sqlx::query("INSERT INTO certificate_providers(id,name,zone_id,zone_name,environment,credential) VALUES('existing','keep name',$1,$2,'production',$3)").bind(&descriptor.zone_id).bind(&descriptor.zone_name).bind(&keep).execute(&db).await?;
        import(&db, &key, root.path(), &descriptor).await?;
        let row = sqlx::query("SELECT id,name,credential FROM certificate_providers")
            .fetch_one(&db)
            .await?;
        assert_eq!(row.try_get::<String, _>("id")?, "existing");
        assert_eq!(row.try_get::<String, _>("name")?, "keep name");
        assert_eq!(row.try_get::<Vec<u8>, _>("credential")?, keep);
        db.close().await;
        Ok(())
    }
}
