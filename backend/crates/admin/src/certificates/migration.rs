//! One-time, transactional import. Once committed, files cannot add, resurrect or
//! override providers. Runtime jobs use only database profiles and credentials.
use super::*;
use std::os::unix::fs::PermissionsExt;

type Initialized = Option<(Settings, PathBuf)>;

fn runtime(root: PathBuf, binary: PathBuf, master: PathBuf) -> Result<(Settings, PathBuf)> {
    ensure!(
        root.is_absolute() && binary.is_absolute() && master.is_absolute(),
        "absolute certificate runtime paths required"
    );
    let meta = std::fs::symlink_metadata(&root)?;
    ensure!(
        meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
        "private certificate root required"
    );
    ensure!(
        crypto::private_file(&master, 32)?.len() == 32,
        "ACME master key required"
    );
    Ok((
        Settings {
            root: root.canonicalize()?,
            binary,
            providers: BTreeMap::new(),
        },
        master,
    ))
}

pub(super) async fn initialize(db: &PgPool, key: &MasterKey) -> Result<Initialized> {
    let catalog = std::env::var_os("OPENWAF_CERTIFICATES_CONFIG").map(PathBuf::from);
    let root = std::env::var_os("OPENWAF_CERTIFICATES_ROOT").map(PathBuf::from);
    if catalog.is_none() && root.is_none() {
        return Ok(None);
    }
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query("SELECT state_root,worker_binary,master_key_file FROM certificate_provider_runtime WHERE singleton=true").fetch_optional(&mut *tx).await?;
    if let Some(row) = existing {
        let root = root.unwrap_or(PathBuf::from(row.try_get::<String, _>("state_root")?));
        let binary = PathBuf::from(row.try_get::<String, _>("worker_binary")?);
        let master = std::env::var_os("OPENWAF_CERTIFICATES_MASTER_KEY_FILE")
            .map(PathBuf::from)
            .unwrap_or(PathBuf::from(row.try_get::<String, _>("master_key_file")?));
        tx.commit().await?;
        return Ok(Some(
            tokio::task::spawn_blocking(move || runtime(root, binary, master)).await??,
        ));
    }
    // All file reads/decryption run outside the async executor and happen only
    // before the durable import marker exists. Never log native input/errors.
    let imported = tokio::task::spawn_blocking(move || -> Result<_> {
        let settings = match catalog
            .map(|p| -> Result<_> { Ok(p.try_exists()?.then_some(p)) })
            .transpose()?
            .flatten()
        {
            Some(path) => Settings::load(&path)?,
            None => Settings {
                root: root.context("certificate root required")?,
                binary: "/usr/local/bin/openwaf-acme".into(),
                providers: BTreeMap::new(),
            },
        };
        let master = std::env::var_os("OPENWAF_CERTIFICATES_MASTER_KEY_FILE")
            .map(PathBuf::from)
            .or_else(|| {
                settings
                    .providers
                    .values()
                    .next()
                    .and_then(|p| p.template["master_key_file"].as_str().map(PathBuf::from))
            })
            .context("ACME master key required")?;
        let (empty, master) = runtime(settings.root.clone(), settings.binary.clone(), master)?;
        let mut imported = Vec::new();
        for provider in settings.providers.into_values() {
            let path = FsPath::new(
                provider.template["cloudflare"]["token_file"]
                    .as_str()
                    .context("token path required")?,
            );
            let bytes = crypto::private_file(path, 4096)?;
            let master = Zeroizing::new(crypto::private_file(
                FsPath::new(
                    provider.template["master_key_file"]
                        .as_str()
                        .context("key path required")?,
                ),
                32,
            )?);
            imported.push((provider, openwaf_cloudflare::open(&bytes, &master)?));
        }
        Ok((empty, master, imported))
    })
    .await??;
    let (settings, master, imported) = imported;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certificate_providers")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        count + imported.len() as i64 <= 16,
        "certificate provider capacity"
    );
    for (provider, credentials) in imported {
        let plain = Zeroizing::new(serde_json::to_vec(&credentials)?);
        let encrypted = key.seal(&providers::secret_name(&provider.id), &plain)?;
        ensure!(sqlx::query("INSERT INTO certificate_providers(id,name,zone_id,zone_name,environment,credential,acme_profile) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(&provider.id).bind(&provider.name).bind(provider.template["cloudflare"]["zone_id"].as_str().context("zone id required")?).bind(&provider.zone).bind(&provider.environment).bind(encrypted).bind(&provider.template).execute(&mut *tx).await?.rows_affected() == 1, "provider import failed");
        audit(
            &mut tx,
            None,
            "certificate_provider.import",
            &provider.id,
            None,
        )
        .await?;
    }
    ensure!(sqlx::query("INSERT INTO certificate_provider_runtime(state_root,worker_binary,master_key_file) VALUES($1,$2,$3)")
        .bind(settings.root.to_str().context("invalid state path")?).bind(settings.binary.to_str().context("invalid binary path")?).bind(master.to_str().context("invalid key path")?).execute(&mut *tx).await?.rows_affected() == 1, "provider import marker failed");
    tx.commit().await?;
    Ok(Some((settings, master)))
}
