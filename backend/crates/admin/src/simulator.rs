//! Security simulator contract: isolated local execution, never forwarded.
use super::*;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub hostname: String,
    pub path: String,
    pub method: String,
    pub client_ip: std::net::IpAddr,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: String,
}
#[derive(Debug)]
pub struct InvalidInput;
impl Input {
    pub fn validate(&self) -> std::result::Result<(), InvalidInput> {
        let uri = self
            .path
            .parse::<http_uri::Uri>()
            .map_err(|_| InvalidInput)?;
        if self.path.len() > 8192
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || uri.scheme().is_some()
            || uri.authority().is_some()
            || openwaf_config::canonical_path(uri.path()).map_err(|_| InvalidInput)? != uri.path()
            || self.path.contains('#')
            || openwaf_config::request_host(&self.hostname).map_err(|_| InvalidInput)?
                != self.hostname
            || self.method.len() > 32
            || self.method.parse::<http_uri::Method>().is_err()
            || self.method != self.method.to_ascii_uppercase()
            || self.body.len() > 65536
            || self.headers.len() > 64
            || self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 16384
            || self.headers.iter().any(|(k, v)| {
                k.parse::<http_uri::HeaderName>().is_err()
                    || v.parse::<http_uri::HeaderValue>().is_err()
                    || matches!(
                        k.to_ascii_lowercase().as_str(),
                        "host"
                            | "content-length"
                            | "transfer-encoding"
                            | "connection"
                            | "trailer"
                            | "te"
                            | "upgrade"
                            | "expect"
                    )
            })
        {
            return Err(InvalidInput);
        }
        let mut names = std::collections::BTreeSet::new();
        if self
            .headers
            .iter()
            .any(|(k, _)| !names.insert(k.to_ascii_lowercase()))
        {
            return Err(InvalidInput);
        }
        Ok(())
    }
}
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn simulate(
        &self,
        snapshot: openwaf_config::Snapshot,
        input: Input,
    ) -> std::result::Result<serde_json::Value, ()>;
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    source: String,
    expected_active_version: i64,
    expected_draft_revision: Option<i64>,
    request: Input,
}
async fn run(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Run>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    input.request.validate().map_err(|_| Error::Invalid)?;
    if !["active", "draft", "compare"].contains(&input.source.as_str()) {
        return Err(Error::Invalid);
    }
    let plane = app.config.as_ref().ok_or(Error::Unavailable)?;
    let backend = app.simulator.as_ref().ok_or(Error::Unavailable)?;
    let active = plane.store.load();
    if active.version != input.expected_active_version {
        return Err(Error::Conflict);
    }
    let mut outputs = serde_json::Map::new();
    let draft = if input.source != "active" {
        let row = sqlx::query(
            "SELECT draft_revision,draft,committed_version FROM config_state WHERE singleton",
        )
        .fetch_one(&app.db)
        .await?;
        if Some(row.try_get::<i64, _>("draft_revision")?) != input.expected_draft_revision
            || row.try_get::<i64, _>("committed_version")? != active.version
        {
            return Err(Error::Conflict);
        }
        Some(
            openwaf_config::resources::persisted_document(row.try_get("draft")?)
                .map_err(|_| Error::Invalid)?,
        )
    } else {
        None
    };
    for (name, document) in [
        (
            "active",
            (input.source != "draft").then(|| active.document.clone()),
        ),
        ("draft", draft),
    ] {
        if let Some(document) = document {
            let snapshot =
                openwaf_config::Snapshot::prepare(active.version, document, &plane.context)
                    .map_err(|_| Error::Invalid)?;
            let mut result = tokio::time::timeout(
                Duration::from_secs(12),
                backend.simulate(snapshot, input.request.clone()),
            )
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
            result["source"] = name.into();
            if name == "draft" {
                result["draft_revision"] = input.expected_draft_revision.into();
            }
            outputs.insert(name.into(), result);
        }
    }
    Ok(Json(
        serde_json::json!({"schema_version":1,"config_version":active.version,"outputs":outputs,"live_state_mutated":false}),
    ))
}
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/security/simulate", post(run))
        .layer(DefaultBodyLimit::max(160 * 1024))
}
