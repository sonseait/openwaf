//! Authenticated certificate requests and Cloudflare provider management.
mod dns;
mod migration;
mod providers;
mod worker;
use crate::*;
use std::{
    collections::BTreeMap,
    path::{Path as FsPath, PathBuf},
};
use tokio::sync::Notify;
pub(crate) use worker::run_worker;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    state_root: PathBuf,
    binary: PathBuf,
    providers: Vec<ProviderSpec>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderSpec {
    id: String,
    name: String,
    environment: String,
    template: PathBuf,
}
#[derive(Clone)]
struct Provider {
    id: String,
    name: String,
    environment: String,
    zone: String,
    fingerprint: String,
    template: serde_json::Value,
    credential: Option<Vec<u8>>,
}
#[derive(Clone)]
struct Settings {
    root: PathBuf,
    binary: PathBuf,
    providers: BTreeMap<String, Provider>,
}
pub(crate) struct Service {
    settings: Option<Settings>,
    reason: Option<&'static str>,
    initialization_failed: bool,
    health: Mutex<serde_json::Value>,
    pub(crate) wake: Notify,
    master_key_file: Option<PathBuf>,
    operations: Semaphore,
    quota: Mutex<(Instant, u16)>,
    mutation: tokio::sync::Mutex<()>,
}
impl Service {
    pub(crate) async fn from_env(db: &PgPool, key: &MasterKey) -> Self {
        let initialized = migration::initialize(db, key).await;
        let initialization_failed = initialized.is_err();
        let (settings, master_key_file, reason) = match initialized {
            Ok(Some((settings, master))) => (Some(settings), Some(master), None),
            Ok(None) => (
                None,
                None,
                Some("Certificate requests are not configured on this server."),
            ),
            Err(_) => (
                None,
                None,
                Some(
                    "Certificate provider migration or runtime configuration is unavailable. Check private state, master keys and database migration before retrying.",
                ),
            ),
        };
        Self {
            settings,
            reason,
            initialization_failed,
            health: Mutex::new(
                serde_json::json!({"state":"starting","observed_at_unix_ms":openwaf_telemetry::now_ms()}),
            ),
            wake: Notify::new(),
            master_key_file,
            operations: Semaphore::new(4),
            quota: Mutex::new((Instant::now(), 0)),
            mutation: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn worker_health(&self, managed: bool) -> serde_json::Value {
        if self.initialization_failed {
            return serde_json::json!({"state":"degraded","reason":self.reason});
        }
        if self.settings.is_none() || !managed {
            return serde_json::json!({"state":"not_configured","reason":self.reason.unwrap_or("Certificate requests require a managed gateway with a TLS listener.")});
        }
        match self.health.lock() {
            Ok(health) => health.clone(),
            Err(_) => {
                serde_json::json!({"state":"unavailable","reason":"certificate_worker_health_unavailable"})
            }
        }
    }
}
impl Settings {
    fn load(path: &FsPath) -> Result<Self> {
        let catalog: Catalog = serde_json::from_slice(&crypto::private_file(path, 65536)?)?;
        ensure!(catalog.root_is_valid(), "invalid certificate catalog");
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&catalog.state_root)?;
        let meta = std::fs::symlink_metadata(&catalog.state_root)?;
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
            "private certificate root required"
        );
        let mut providers = BTreeMap::new();
        for spec in catalog.providers {
            let mut template: serde_json::Value =
                serde_json::from_slice(&crypto::private_file(&spec.template, 65536)?)?;
            let zone = template["cloudflare"]["zone_name"]
                .as_str()
                .context("zone required")?;
            let zone = openwaf_config::hostname(zone)?;
            ensure!(
                zone.contains('.')
                    && !zone.starts_with("*.")
                    && zone.parse::<std::net::IpAddr>().is_err(),
                "invalid zone"
            );
            let zone_id = template["cloudflare"]["zone_id"]
                .as_str()
                .context("zone id required")?;
            ensure!(
                zone_id.len() == 32 && zone_id.bytes().all(|v| v.is_ascii_hexdigit()),
                "invalid zone id"
            );
            ensure!(
                template.is_object() && template.get("challenge_listen").is_none(),
                "DNS-01 required"
            );
            let directory = reqwest::Url::parse(
                template["directory_url"]
                    .as_str()
                    .context("directory required")?,
            )?;
            ensure!(
                directory.scheme() == "https"
                    && directory.host_str().is_some()
                    && directory.username().is_empty()
                    && directory.password().is_none()
                    && directory.fragment().is_none(),
                "invalid CA directory"
            );
            // Environment labels cannot make staging certificates appear to be public TLS.
            ensure!(
                spec.environment == "staging" || spec.environment == "production",
                "invalid CA environment"
            );
            if directory.host_str() == Some("acme-staging-v02.api.letsencrypt.org") {
                ensure!(
                    spec.environment == "staging",
                    "staging environment required"
                );
            }
            for value in [
                &template["master_key_file"],
                &template["tls_manifest"],
                &template["cloudflare"]["token_file"],
            ] {
                ensure!(
                    value.as_str().is_some_and(|p| FsPath::new(p).is_absolute()),
                    "absolute ACME paths required"
                );
            }
            if let Some(live) = std::env::var_os("OPENWAF_TLS_MANIFEST") {
                let manifest = FsPath::new(
                    template["tls_manifest"]
                        .as_str()
                        .context("manifest required")?,
                );
                let same = same_manifest(manifest, FsPath::new(&live))?;
                ensure!(
                    spec.environment != "staging" || !same,
                    "staging cannot publish to live TLS"
                );
                ensure!(
                    spec.environment != "production" || same,
                    "production must publish to live TLS"
                );
            }
            // Consent is recorded for each authenticated request; templates need no secrets in UI.
            template["terms_of_service_agreed"] = true.into();
            template["cloudflare"]["zone_name"] = zone.clone().into();
            template
                .as_object_mut()
                .context("template object")?
                .remove("hostname");
            template
                .as_object_mut()
                .context("template object")?
                .remove("state_dir");
            let fingerprint = crypto::hex(&sha256(&serde_json::to_vec(&template)?));
            ensure!(
                providers
                    .insert(
                        spec.id.clone(),
                        Provider {
                            id: spec.id,
                            name: spec.name,
                            environment: spec.environment,
                            zone,
                            fingerprint,
                            template,
                            credential: None
                        }
                    )
                    .is_none(),
                "duplicate provider"
            );
        }
        Ok(Self {
            root: catalog.state_root.canonicalize()?,
            binary: catalog.binary,
            providers,
        })
    }
}
fn same_manifest(a: &FsPath, b: &FsPath) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    if let (Ok(a), Ok(b)) = (a.metadata(), b.metadata())
        && a.dev() == b.dev()
        && a.ino() == b.ino()
    {
        return Ok(true);
    }
    fn resolve(path: &FsPath) -> Result<PathBuf> {
        let mut suffix = Vec::new();
        let mut cursor = path;
        loop {
            match cursor.canonicalize() {
                Ok(mut base) => {
                    for part in suffix.into_iter().rev() {
                        base.push(part);
                    }
                    return Ok(base);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    suffix.push(
                        cursor
                            .file_name()
                            .context("invalid TLS manifest")?
                            .to_owned(),
                    );
                    cursor = cursor.parent().context("TLS manifest parent required")?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(resolve(a)? == resolve(b)?)
}
impl Catalog {
    fn root_is_valid(&self) -> bool {
        self.state_root.is_absolute()
            && self.binary.is_absolute()
            && self.providers.len() <= 8
            && self.providers.iter().all(|p| {
                valid_name(&p.id)
                    && !p.name.trim().is_empty()
                    && p.name.len() <= 100
                    && p.template.is_absolute()
            })
    }
}
fn hostname(value: &str) -> ApiResult<String> {
    let value = value.trim().to_ascii_lowercase();
    let value = value.strip_suffix('.').unwrap_or(&value);
    let base = value.strip_prefix("*.").unwrap_or(value);
    let normalized = openwaf_config::hostname(base).map_err(|_| Error::Invalid)?;
    if normalized != base
        || base.starts_with("*.")
        || base.parse::<std::net::IpAddr>().is_ok()
        || value.len() > 253
    {
        return Err(Error::Invalid);
    }
    Ok(value.to_owned())
}
fn in_zone(hostname: &str, zone: &str) -> bool {
    let base = hostname.strip_prefix("*.").unwrap_or(hostname);
    base == zone || base.ends_with(&format!(".{zone}"))
}
fn live(app: &App, hostname: &str) -> Option<openwaf_tls::CertificateStatus> {
    let store = app.application_tls.as_ref()?;
    if hostname.starts_with("*.") {
        store.certificate(hostname)
    } else {
        store.certificate_for(hostname)
    }
}
fn base_settings(app: &App) -> ApiResult<&Settings> {
    if app.config.is_none() || app.application_tls.is_none() {
        return Err(Error::Unavailable);
    }
    app.certificates.settings.as_ref().ok_or(Error::Unavailable)
}
async fn settings(app: &App) -> ApiResult<Settings> {
    let mut settings = base_settings(app)?.clone();
    providers::extend(app, &mut settings).await?;
    Ok(settings)
}
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/certificates", get(inventory).post(request))
        .route("/api/v1/certificates/retry", post(retry))
        .merge(providers::routes())
}
async fn inventory(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let settings = if base_settings(&app).is_ok() {
        Some(settings(&app).await?)
    } else {
        None
    };
    let profiles: Vec<_> = settings.as_ref().map(|s| s.providers.values().map(|p| serde_json::json!({"id":p.id,"name":p.name,"zone_name":p.zone,"environment":p.environment,"challenge":"dns-01","provider":"cloudflare"})).collect()).unwrap_or_default();
    let rows = sqlx::query("SELECT hostname,provider_id,state,covered_by_hostname,attempts,last_error_code,next_attempt::text AS next_attempt,updated_at::text AS updated_at FROM certificate_requests ORDER BY hostname LIMIT 129").fetch_all(&app.db).await?;
    let mut jobs = Vec::new();
    for row in rows {
        let hostname: String = row.try_get("hostname")?;
        jobs.push(serde_json::json!({"hostname":hostname,"provider_id":row.try_get::<String,_>("provider_id")?,"state":row.try_get::<String,_>("state")?,"covered_by_hostname":row.try_get::<Option<String>,_>("covered_by_hostname")?,"attempts":row.try_get::<i32,_>("attempts")?,"last_error_code":row.try_get::<Option<String>,_>("last_error_code")?,"next_attempt":row.try_get::<String,_>("next_attempt")?,"updated_at":row.try_get::<String,_>("updated_at")?,"loaded_certificate":live(&app,&hostname)}));
    }
    Ok(Json(
        serde_json::json!({"enabled":settings.is_some(),"unavailable_reason":app.certificates.reason.or_else(|| (app.config.is_none() || app.application_tls.is_none()).then_some("Certificate requests require a managed gateway with a TLS listener.")),"providers":profiles,"requests":jobs,"worker":app.certificates.health.lock().map_err(|_|Error::Unavailable)?.clone(),"observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    hostname: String,
    provider_id: String,
    terms_of_service_agreed: bool,
}
async fn request(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Request>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    let settings = settings(&app).await?;
    let hostname = hostname(&input.hostname)?;
    let provider = settings
        .providers
        .get(&input.provider_id)
        .ok_or(Error::Invalid)?;
    if !input.terms_of_service_agreed || !in_zone(&hostname, &provider.zone) {
        return Err(Error::Invalid);
    }
    // Existing exact certificates may have an external renewal owner. Do not take over.
    if app
        .application_tls
        .as_ref()
        .is_some_and(|s| s.certificates().iter().any(|c| c.hostname == hostname))
    {
        return Err(Error::Conflict);
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    let reserved: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM bootstrap_certificate_ownership WHERE hostname=$1)",
    )
    .bind(&hostname)
    .fetch_one(&mut *tx)
    .await?;
    if reserved {
        return Err(Error::Conflict);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certificate_requests")
        .fetch_one(&mut *tx)
        .await?;
    if count >= 128 {
        return Err(Error::Conflict);
    }
    // Suppress duplicate ownership of the same hostname in the Applications queue.
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM application_certificates WHERE hostname=$1 AND state<>'covered')").bind(&hostname).fetch_one(&mut *tx).await?;
    if active {
        return Err(Error::Conflict);
    }
    let result = sqlx::query("INSERT INTO certificate_requests(hostname,provider_id,provider_fingerprint,requested_by) VALUES($1,$2,$3,$4) ON CONFLICT(hostname) DO NOTHING").bind(&hostname).bind(&provider.id).bind(&provider.fingerprint).bind(auth.id).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "certificate.request",
        &hostname,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    app.certificates.wake.notify_one();
    Ok(StatusCode::ACCEPTED)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retry {
    hostname: String,
}
async fn retry(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Retry>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    let settings = settings(&app).await?;
    let hostname = hostname(&input.hostname)?;
    let mut tx = app.db.begin().await?;
    let row = sqlx::query("SELECT provider_id,provider_fingerprint,state FROM certificate_requests WHERE hostname=$1 FOR UPDATE").bind(&hostname).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
    if row.try_get::<String, _>("state")? != "degraded" {
        return Err(Error::Conflict);
    }
    let id: String = row.try_get("provider_id")?;
    let fingerprint: String = row.try_get("provider_fingerprint")?;
    if !settings
        .providers
        .get(&id)
        .is_some_and(|p| p.fingerprint == fingerprint)
    {
        return Err(Error::Unavailable);
    }
    let result = sqlx::query("UPDATE certificate_requests SET state='pending',attempts=0,last_error_code=NULL,next_attempt=now(),updated_at=now() WHERE hostname=$1 AND state='degraded'").bind(&hostname).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "certificate.retry",
        &hostname,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    app.certificates.wake.notify_one();
    Ok(StatusCode::NO_CONTENT)
}
pub async fn run(app: &App, stopped: tokio::sync::watch::Receiver<bool>) {
    crate::applications::certificates::run(app, stopped).await;
}

pub(crate) async fn cycle(
    app: &App,
    stopped: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    worker::cycle(app, stopped).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_input_and_zone_boundaries() {
        assert_eq!(
            hostname(" *.Sub.Example.com. ").ok().as_deref(),
            Some("*.sub.example.com")
        );
        for value in [
            "*.*.example.com",
            "https://example.com",
            "127.0.0.1",
            "a.*.example.com",
            "*.127.0.0.1",
        ] {
            assert!(hostname(value).is_err(), "{value}");
        }
        assert!(in_zone("*.sub.example.com", "example.com"));
        assert!(!in_zone("*.notexample.com", "example.com"));
    }
    #[test]
    fn staging_manifest_cannot_alias_live_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let live = root.path().join("manifest.json");
        std::fs::write(&live, b"fixture")?;
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(root.path(), &alias)?;
        assert!(same_manifest(&live, &alias.join("manifest.json"))?);
        let future = root.path().join("new/manifest.json");
        assert!(same_manifest(&future, &alias.join("new/manifest.json"))?);
        assert!(!same_manifest(&live, &future)?);
        Ok(())
    }
}
