//! Authenticated gateway-side services. Standalone Admin cannot probe a different namespace.
use super::*;
use axum::extract::Query;
use openwaf_config::{Address, Endpoint, Protocol, source::Source};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Docker,
    HostPorts,
}
impl Kind {
    pub fn op(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::HostPorts => "host-ports",
        }
    }
    pub fn index(self) -> usize {
        match self {
            Self::Docker => 0,
            Self::HostPorts => 1,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct Candidate {
    pub id: String,
    pub address: Option<Address>,
    pub source: Source,
    pub selectable: bool,
    pub unavailable_reason: Option<&'static str>,
    pub verification: &'static str,
}
#[derive(Clone, Serialize)]
pub struct Inventory {
    pub schema_version: u8,
    pub source: Kind,
    pub collection_scope: &'static str,
    pub collector_available: bool,
    pub docker_events_connected: Option<bool>,
    pub stale: bool,
    pub error: Option<&'static str>,
    pub observed_at_unix_ms: Option<u64>,
    pub items: serde_json::Value,
    pub candidates: Vec<Candidate>,
    pub candidates_truncated: bool,
}
#[derive(Clone, Copy, Debug)]
pub enum Failure {
    Invalid,
    Unavailable,
    RateLimited,
}
impl From<Failure> for Error {
    fn from(error: Failure) -> Self {
        match error {
            Failure::Invalid => Self::Invalid,
            Failure::Unavailable => Self::Unavailable,
            Failure::RateLimited => Self::Unavailable,
        }
    }
}
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn inventory(&self, kind: Kind) -> Result<Arc<Inventory>, Failure>;
    async fn refresh(&self) -> Result<serde_json::Value, Failure>;
    async fn test(&self, endpoint: Endpoint) -> Result<serde_json::Value, Failure>;
}
fn backend(app: &App) -> ApiResult<&Arc<dyn Backend>> {
    app.discovery.as_ref().ok_or(Error::Unavailable)
}
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/discovery/docker", get(docker))
        .route("/api/v1/discovery/host-ports", get(host_ports))
        .route(
            "/api/v1/discovery/docker/candidates",
            get(docker_candidates),
        )
        .route(
            "/api/v1/discovery/host-ports/candidates",
            get(host_candidates),
        )
        .route("/api/v1/discovery/refresh", post(refresh))
        .route("/api/v1/discovery/select", post(select))
        .route("/api/v1/upstreams/test", post(test))
}
async fn docker(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Inventory>> {
    authenticate(&app, &headers, false).await?;
    let inventory = backend(&app)?.inventory(Kind::Docker).await?;
    Ok(Json(legacy(&inventory)))
}
async fn host_ports(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Inventory>> {
    authenticate(&app, &headers, false).await?;
    let inventory = backend(&app)?.inventory(Kind::HostPorts).await?;
    Ok(Json(legacy(&inventory)))
}

// Preserve the old inventory wire limit; picker pages omit raw inventory items.
fn legacy(inventory: &Inventory) -> Inventory {
    Inventory {
        candidates: inventory.candidates.iter().take(1024).cloned().collect(),
        candidates_truncated: inventory.candidates_truncated || inventory.candidates.len() > 1024,
        items: inventory.items.clone(),
        ..metadata(inventory)
    }
}
fn metadata(inventory: &Inventory) -> Inventory {
    Inventory {
        schema_version: inventory.schema_version,
        source: inventory.source,
        collection_scope: inventory.collection_scope,
        collector_available: inventory.collector_available,
        docker_events_connected: inventory.docker_events_connected,
        stale: inventory.stale,
        error: inventory.error,
        observed_at_unix_ms: inventory.observed_at_unix_ms,
        items: serde_json::Value::Null,
        candidates: vec![],
        candidates_truncated: inventory.candidates_truncated,
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}
#[derive(Serialize)]
struct CandidatePage {
    schema_version: u8,
    source: Kind,
    collection_scope: &'static str,
    collector_available: bool,
    docker_events_connected: Option<bool>,
    stale: bool,
    error: Option<&'static str>,
    observed_at_unix_ms: Option<u64>,
    revision: String,
    total: usize,
    limit: usize,
    next_cursor: Option<String>,
    candidates_truncated: bool,
    candidates: Vec<Candidate>,
}

// Observation times advance every reconcile without changing the selectable set.
// Hash stable IDs and current availability, not timestamps; no snapshot history,
// client-supplied cache keys or cursor registry can accumulate in memory.
fn revision(inventory: &Inventory) -> Result<String, Error> {
    let mut hash = openssl::sha::Sha256::new();
    let metadata = serde_json::to_vec(&(
        inventory.schema_version,
        inventory.source,
        inventory.collector_available,
        inventory.docker_events_connected,
        inventory.stale,
        inventory.error,
        inventory.candidates_truncated,
    ))
    .map_err(|_| Error::Unavailable)?;
    hash.update(&metadata);
    for candidate in &inventory.candidates {
        let bytes = serde_json::to_vec(&(
            &candidate.id,
            &candidate.address,
            candidate.selectable,
            candidate.unavailable_reason,
            candidate.verification,
        ))
        .map_err(|_| Error::Unavailable)?;
        hash.update(&bytes);
    }
    Ok(crypto::hex(&hash.finish()))
}
fn page(inventory: &Inventory, query: PageQuery) -> ApiResult<CandidatePage> {
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(Error::Invalid);
    }
    let revision = revision(inventory)?;
    let offset = match query.cursor {
        None => 0,
        Some(cursor) => {
            if cursor.len() > 80 {
                return Err(Error::Invalid);
            }
            let (previous, offset) = cursor.split_once(':').ok_or(Error::Invalid)?;
            if previous.len() != 64
                || !previous.bytes().all(|b| b.is_ascii_hexdigit())
                || offset.is_empty()
                || !offset.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Error::Invalid);
            }
            let offset = offset.parse::<usize>().map_err(|_| Error::Invalid)?;
            if previous != revision {
                return Err(Error::Conflict);
            }
            if offset == 0 || offset >= inventory.candidates.len() {
                return Err(Error::Invalid);
            }
            offset
        }
    };
    let end = (offset + limit).min(inventory.candidates.len());
    Ok(CandidatePage {
        schema_version: inventory.schema_version,
        source: inventory.source,
        collection_scope: inventory.collection_scope,
        collector_available: inventory.collector_available,
        docker_events_connected: inventory.docker_events_connected,
        stale: inventory.stale,
        error: inventory.error,
        observed_at_unix_ms: inventory.observed_at_unix_ms,
        total: inventory.candidates.len(),
        limit,
        next_cursor: (end < inventory.candidates.len()).then(|| format!("{revision}:{end}")),
        revision,
        candidates_truncated: inventory.candidates_truncated,
        candidates: inventory.candidates[offset..end].to_vec(),
    })
}
async fn candidates(
    app: Arc<App>,
    headers: HeaderMap,
    kind: Kind,
    query: PageQuery,
) -> ApiResult<Json<CandidatePage>> {
    authenticate(&app, &headers, false).await?;
    // Validate cheap bounds before collector work, even for a first page.
    if query.limit.is_some_and(|limit| !(1..=100).contains(&limit))
        || query
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > 80)
    {
        return Err(Error::Invalid);
    }
    let inventory = backend(&app)?.inventory(kind).await?;
    Ok(Json(page(&inventory, query)?))
}
async fn docker_candidates(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<CandidatePage>> {
    candidates(app, headers, Kind::Docker, query).await
}
async fn host_candidates(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<CandidatePage>> {
    candidates(app, headers, Kind::HostPorts, query).await
}
async fn refresh(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    match backend(&app)?.refresh().await {
        Err(Failure::RateLimited) => Err(Error::RefreshLimited),
        result => Ok(Json(result?)),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    source: Kind,
    candidate_id: String,
    protocol: Protocol,
    tls_server_name: Option<String>,
    #[serde(default = "openwaf_config::default_tls_verify")]
    tls_verify: bool,
}
async fn select(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Selection>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    if input.candidate_id.len() != 64 || !input.candidate_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Invalid);
    }
    let inventory = backend(&app)?.inventory(input.source).await?;
    if inventory.stale || !inventory.collector_available {
        return Err(Error::Conflict);
    }
    let candidate = inventory
        .candidates
        .iter()
        .find(|c| c.id == input.candidate_id)
        .ok_or(Error::NotFound)?;
    if !candidate.selectable {
        return Err(Error::Conflict);
    }
    let endpoint = Endpoint {
        weight: 1,
        address: candidate.address.clone().ok_or(Error::Conflict)?,
        protocol: input.protocol,
        tls_server_name: input.tls_server_name,
        tls_verify: input.tls_verify,
        source: Some(candidate.source.clone()),
    };
    // Same validator as save/apply; selection never writes a draft or active config.
    let plane = app.config.as_ref().ok_or(Error::Unavailable)?;
    let snapshot = openwaf_config::Snapshot::prepare(
        0,
        openwaf_config::Document {
            upstreams: vec![openwaf_config::Upstream {
                balancing: Default::default(),
                affinity: None,
                id: "selection".into(),
                endpoints: vec![endpoint],
                timeouts: Default::default(),
                health: Default::default(),
            }],
            ..Default::default()
        },
        &plane.context,
    )
    .map_err(|_| Error::Invalid)?;
    Ok(Json(
        serde_json::json!({"endpoint":snapshot.document.upstreams[0].endpoints[0], "verification":"not_tested"}),
    ))
}
async fn test(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(endpoint): Json<Endpoint>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    Ok(Json(backend(&app)?.test(endpoint).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> Inventory {
        Inventory {
            schema_version: 1,
            source: Kind::HostPorts,
            collection_scope: "collector_network_namespace",
            collector_available: true,
            docker_events_connected: None,
            stale: false,
            error: None,
            observed_at_unix_ms: Some(1),
            items: serde_json::json!([]),
            candidates: (1..=3)
                .map(|port| Candidate {
                    id: format!("{port:064x}"),
                    address: Some(format!("127.0.0.1:{port}").parse().unwrap()),
                    source: Source::HostPort {
                        bind_address: "127.0.0.1".parse().unwrap(),
                        port,
                        observed_at_unix_ms: 1,
                    },
                    selectable: true,
                    unavailable_reason: None,
                    verification: "not_tested",
                })
                .collect(),
            candidates_truncated: false,
        }
    }

    #[test]
    fn pages_keep_membership_across_observation_updates_and_reject_changed_availability() {
        let mut inventory = inventory();
        let first = page(
            &inventory,
            PageQuery {
                limit: Some(2),
                cursor: None,
            },
        )
        .unwrap_or_else(|_| panic!("first page"));
        assert_eq!(first.total, 3);
        assert_eq!(first.candidates.len(), 2);
        let cursor = first.next_cursor.clone();
        inventory.observed_at_unix_ms = Some(2);
        for candidate in &mut inventory.candidates {
            if let Source::HostPort {
                observed_at_unix_ms,
                ..
            } = &mut candidate.source
            {
                *observed_at_unix_ms = 2;
            }
        }
        let second = page(
            &inventory,
            PageQuery {
                limit: Some(1),
                cursor: cursor.clone(),
            },
        )
        .unwrap_or_else(|_| panic!("second page"));
        assert_eq!(second.revision, first.revision);
        assert_eq!(second.candidates[0].id, inventory.candidates[2].id);
        assert!(second.next_cursor.is_none());
        inventory.candidates[0].selectable = false;
        assert!(matches!(
            page(
                &inventory,
                PageQuery {
                    limit: None,
                    cursor
                }
            ),
            Err(Error::Conflict)
        ));
    }

    #[test]
    fn empty_pages_and_invalid_limits_offsets_are_bounded() {
        let mut inventory = inventory();
        for limit in [0, 101, usize::MAX] {
            assert!(matches!(
                page(
                    &inventory,
                    PageQuery {
                        limit: Some(limit),
                        cursor: None
                    }
                ),
                Err(Error::Invalid)
            ));
        }
        let revision = revision(&inventory).unwrap_or_else(|_| panic!("revision"));
        for suffix in ["0", "3", "-1", "999999999999999999999999999999", "1:2", ""] {
            assert!(matches!(
                page(
                    &inventory,
                    PageQuery {
                        limit: None,
                        cursor: Some(format!("{revision}:{suffix}"))
                    }
                ),
                Err(Error::Invalid)
            ));
        }
        inventory.candidates.clear();
        let empty = page(&inventory, PageQuery::default()).unwrap_or_else(|_| panic!("empty"));
        assert_eq!(empty.total, 0);
        assert!(empty.next_cursor.is_none() && empty.candidates.is_empty());
    }
}
