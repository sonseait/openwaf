//! Pure bounded validation/routing and immutable snapshots. No I/O or storage.
#![forbid(unsafe_code)]
pub mod access;
pub mod affinity;
pub mod application;
pub mod balancing;
pub mod error_pages;
pub mod headers;
pub mod health;
pub mod maintenance;
pub mod middleware;
pub mod operations;
pub mod password;
pub mod playground;
pub mod record_body;
pub mod requests;
pub mod resources;
pub mod response;
pub mod retry;
pub mod source;
pub mod traffic;
pub mod waf;

use arc_swap::ArcSwap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(default, skip_serializing_if = "access::Policy::is_default")]
    pub global_rules: access::Policy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_pages: Vec<error_pages::Page>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default)]
    pub record_body: record_body::Policy,
    #[serde(default)]
    pub application: Option<application::Target>,
    #[serde(default)]
    pub maintenance: Option<maintenance::Policy>,
    #[serde(default)]
    pub password_protect: Option<password::Policy>,
    #[serde(default)]
    pub error_pages: Vec<error_pages::Page>,
    #[serde(default)]
    pub middleware: middleware::Policy,
    #[serde(default)]
    pub profile: Option<traffic::Profile>,
    #[serde(default)]
    pub content: Option<traffic::Content>,
    #[serde(default)]
    pub admission_class: Option<traffic::Class>,
    #[serde(default)]
    pub admission: resources::Admission,
    #[serde(default)]
    pub timeouts: Option<Timeouts>,
    #[serde(default)]
    pub retry: retry::Policy,
    #[serde(default)]
    pub body: Option<retry::Body>,
    pub id: String,
    pub hostname: String,
    pub path: String,
    pub path_match: PathMatch,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub upstream: String,
    #[serde(default)]
    pub redirect: Option<response::Redirect>,
    #[serde(default)]
    pub security_headers: response::SecurityHeaders,
    #[serde(default)]
    pub access: access::Policy,
    #[serde(default)]
    pub waf: Option<waf::Policy>,
}
// Profile copies persist every effective retry/replay field. Admission is always
// explicit so stored versions retain their quotas when defaults change. Other
// legacy fields retain the previous default-omitting wire format. Destructuring
// makes added fields a compile error until their serialization contract is chosen.
impl Serialize for Route {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let Self {
            record_body,
            application,
            maintenance,
            password_protect,
            error_pages,
            middleware,
            profile,
            content,
            admission_class,
            admission,
            timeouts,
            retry,
            body,
            id,
            hostname,
            path,
            path_match,
            methods,
            upstream,
            redirect,
            security_headers,
            access,
            waf,
        } = self;
        let mut map = serializer.serialize_map(None)?;
        if !record_body.is_default() {
            map.serialize_entry("record_body", record_body)?;
        }
        if let Some(target) = application {
            map.serialize_entry("application", target)?;
        }
        if let Some(policy) = maintenance {
            map.serialize_entry("maintenance", policy)?;
        }
        if let Some(policy) = password_protect {
            map.serialize_entry("password_protect", policy)?;
        }
        if !error_pages.is_empty() {
            map.serialize_entry("error_pages", error_pages)?;
        }
        if !middleware.is_default() {
            map.serialize_entry("middleware", middleware)?;
        }
        if let Some(profile) = profile {
            map.serialize_entry("profile", profile)?;
        }
        if let Some(content) = content {
            map.serialize_entry("content", content)?;
        }
        if let Some(class) = admission_class {
            map.serialize_entry("admission_class", class)?;
        }
        map.serialize_entry("admission", admission)?;
        if let Some(timeouts) = timeouts {
            map.serialize_entry("timeouts", timeouts)?;
        }
        if profile.is_some() || !retry.is_default() {
            map.serialize_entry("retry", retry)?;
        }
        if let Some(body) = body {
            map.serialize_entry("body", body)?;
        }
        map.serialize_entry("id", id)?;
        map.serialize_entry("hostname", hostname)?;
        map.serialize_entry("path", path)?;
        map.serialize_entry("path_match", path_match)?;
        map.serialize_entry("methods", methods)?;
        if !upstream.is_empty() {
            map.serialize_entry("upstream", upstream)?;
        }
        if let Some(redirect) = redirect {
            map.serialize_entry("redirect", redirect)?;
        }
        if !security_headers.is_default() {
            map.serialize_entry("security_headers", security_headers)?;
        }
        if !access.is_default() {
            map.serialize_entry("access", access)?;
        }
        if let Some(waf) = waf {
            map.serialize_entry("waf", waf)?;
        }
        map.end()
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathMatch {
    Exact,
    Prefix,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<affinity::Settings>,
    #[serde(default, skip_serializing_if = "balancing::Settings::is_default")]
    pub balancing: balancing::Settings,
    pub id: String,
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default, skip_serializing_if = "health::Settings::is_default")]
    pub health: health::Settings,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    #[serde(
        default = "balancing::default_weight",
        skip_serializing_if = "balancing::normal_weight"
    )]
    pub weight: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<source::Source>,
    pub address: Address,
    pub protocol: Protocol,
    pub tls_server_name: Option<String>,
    #[serde(
        default = "default_tls_verify",
        skip_serializing_if = "is_tls_verified"
    )]
    pub tls_verify: bool,
}
pub fn default_tls_verify() -> bool {
    true
}
fn is_tls_verified(value: &bool) -> bool {
    *value
}
/// Numeric socket or DNS authority with an explicit port; never a URL.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address(String);
impl std::str::FromStr for Address {
    type Err = Validation;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(socket) = value.parse::<SocketAddr>() {
            return Ok(Self(socket.to_string()));
        }
        let authority: http::uri::Authority = value.parse().map_err(|_| Validation::Endpoint)?;
        let port = authority.port_u16().ok_or(Validation::Endpoint)?;
        if value.contains('@') {
            return Err(Validation::Endpoint);
        }
        let host = hostname(authority.host())?;
        // IP literals must use the unambiguous SocketAddr syntax above.
        if host.parse::<IpAddr>().is_ok() {
            return Err(Validation::Endpoint);
        }
        Ok(Self(format!("{host}:{port}")))
    }
}
impl TryFrom<String> for Address {
    type Error = Validation;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
impl From<Address> for String {
    fn from(value: Address) -> Self {
        value.0
    }
}
impl Address {
    pub fn socket(&self) -> Option<SocketAddr> {
        self.0.parse().ok()
    }
    pub fn host(&self) -> String {
        self.socket()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| self.0.rsplit_once(':').map_or("", |(h, _)| h).to_owned())
    }
    pub fn port(&self) -> u16 {
        self.0
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(0)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Timeouts {
    /// Wall-clock lifetime after request headers, including inspection and streaming.
    pub total_ms: u64,
    pub connect_ms: u64,
    /// TLS handshake only; absent inherits connect_ms for existing documents.
    pub tls_ms: Option<u64>,
    /// Absolute wait for final headers after upstream request headers are written.
    pub header_ms: Option<u64>,
    /// Upstream body/WS read idle; absent inherits read_ms.
    pub response_idle_ms: Option<u64>,
    pub read_ms: u64,
    pub write_ms: u64,
    pub idle_ms: u64,
}
impl Default for Timeouts {
    fn default() -> Self {
        Self {
            total_ms: 30000,
            connect_ms: 3000,
            tls_ms: None,
            header_ms: None,
            response_idle_ms: None,
            read_ms: 10000,
            write_ms: 10000,
            idle_ms: 30000,
        }
    }
}
impl Timeouts {
    pub fn valid(&self) -> bool {
        (1..=30000).contains(&self.connect_ms)
            && self.tls_ms.is_none_or(|v| (1..=30000).contains(&v))
            && self.header_ms.is_none_or(|v| (1..=86400000).contains(&v))
            && self
                .response_idle_ms
                .is_none_or(|v| (1..=120000).contains(&v))
            && (1..=86400000).contains(&self.total_ms)
            && [self.read_ms, self.write_ms, self.idle_ms]
                .iter()
                .all(|v| (1..=120000).contains(v))
    }
}
/// Operator-supplied listener/local addresses, never supplied by an API draft.
#[derive(Clone)]
pub struct Context {
    pub listeners: Vec<SocketAddr>,
    pub local_ips: Vec<IpAddr>,
}
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Validation {
    #[error(
        "invalid error pages: use unique 400–599 statuses and nonempty HTML up to 16 KiB each (maximum 16 pages per scope)"
    )]
    ErrorPages,
    #[error(
        "invalid route maintenance: use a nonempty message up to 512 UTF-8 bytes and retry_after_seconds 1–86400"
    )]
    Maintenance,
    #[error("invalid password protection policy")]
    PasswordProtect,
    #[error("invalid route middleware or ForwardAuth policy")]
    Middleware,
    #[error("invalid resource budgets or admission quota")]
    Resources,
    #[error("configuration resource limit exceeded")]
    Limit,
    #[error("invalid or duplicate identifier")]
    Identifier,
    #[error("invalid hostname")]
    Hostname,
    #[error("invalid or ambiguous path")]
    Path,
    #[error("invalid or duplicate HTTP method")]
    Method,
    #[error("route references missing upstream")]
    Reference,
    #[error("invalid application target")]
    Application,
    #[error("ambiguous route precedence")]
    Ambiguous,
    #[error("invalid or duplicate endpoint")]
    Endpoint,
    #[error("upstream points to an OpenWAF listener")]
    ProxyLoop,
    #[error("invalid timeout")]
    Timeout,
    #[error("invalid health check settings")]
    Health,
    #[error("invalid redirect URL, status or fallback upstream")]
    Redirect,
    #[error("possible redirect host cycle")]
    RedirectLoop,
    #[error("invalid security response headers")]
    SecurityHeaders,
    #[error("invalid access, country or traffic rate policy")]
    Access,
    #[error("invalid WAF policy or exclusion reason")]
    Waf,
    #[error("invalid retry, replay or body settings")]
    Retry,
    #[error("invalid body recording policy")]
    RecordBody,
    #[error("invalid traffic profile or content contract")]
    Content,
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
pub fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}
pub fn hostname(value: &str) -> Result<String, Validation> {
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.parse::<IpAddr>().is_ok() {
        return Ok(value);
    }
    if value.is_empty()
        || value.len() > 253
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(Validation::Hostname);
    }
    Ok(value)
}
pub fn request_host(value: &str) -> Result<String, Validation> {
    let authority: http::uri::Authority = value.parse().map_err(|_| Validation::Hostname)?;
    if authority.as_str().contains('@')
        || (authority.as_str().len() != authority.host().len() && authority.port_u16().is_none())
    {
        return Err(Validation::Hostname);
    }
    hostname(
        authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']'),
    )
}
/// Decode unreserved bytes only. Reject dot segments, encoded separators and
/// malformed encodings so routing cannot disagree on path boundaries.
pub fn canonical_path(value: &str) -> Result<String, Validation> {
    if !value.starts_with('/') || value.len() > 2048 {
        return Err(Validation::Path);
    }
    let mut out = String::new();
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or(Validation::Path)?;
            let lo = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or(Validation::Path)?;
            let decoded = (hi * 16 + lo) as u8;
            if decoded <= 32 || decoded == 127 || b"/\\?#%".contains(&decoded) {
                return Err(Validation::Path);
            }
            if decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded) {
                out.push(decoded as char);
            } else {
                out.push_str(&format!("%{decoded:02X}"));
            }
        } else if !(33..127).contains(&b) || b"\\?#".contains(&b) {
            return Err(Validation::Path);
        } else {
            out.push(b as char);
        }
    }
    if out.contains("//")
        || out
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(Validation::Path);
    }
    Ok(out)
}
impl Context {
    pub fn denies(&self, address: SocketAddr) -> bool {
        let ip = normalized_ip(address.ip());
        self.listeners.iter().any(|listener| {
            listener.port() == address.port()
                && (normalized_ip(listener.ip()) == ip
                    || (listener.ip().is_unspecified()
                        && (ip.is_loopback()
                            || self
                                .local_ips
                                .iter()
                                .any(|local| normalized_ip(*local) == ip))))
        })
    }
}
pub fn validate_address(address: SocketAddr, context: &Context) -> Result<(), Validation> {
    let ip = normalized_ip(address.ip());
    if address.port() == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
    {
        return Err(Validation::Endpoint);
    }
    if context.denies(address) {
        return Err(Validation::ProxyLoop);
    }
    Ok(())
}
pub struct Snapshot {
    /// Decrypted only by the control plane, never serialized or logged.
    pub password_verifiers: Vec<Option<Arc<zeroize::Zeroizing<String>>>>,
    pub waf_usage: Vec<waf::Usage>,
    pub coverage: Vec<traffic::Coverage>,
    pub version: i64,
    pub document: Document,
    counters: Vec<AtomicUsize>,
    selectors: Vec<balancing::Selector>,
    upstream_index: BTreeMap<String, usize>,
    pub health: health::Health,
    /// Prepared runtime resources supplied before control-plane publication.
    /// Pure validation cannot construct these; proxy adapters check their type.
    pub prepared: Option<Arc<dyn std::any::Any + Send + Sync>>,
    pub applications: Option<Arc<dyn std::any::Any + Send + Sync>>,
}
impl Snapshot {
    pub fn prepare(
        version: i64,
        mut document: Document,
        context: &Context,
    ) -> Result<Self, Validation> {
        if version < 0
            || document.routes.len() > 128
            || document.upstreams.len() > 64
            || document.trusted_proxies.len() > 32
            || serde_json::to_vec(&document)
                .map_err(|_| Validation::Limit)?
                .len()
                > MAX_CONFIG_BYTES
        {
            return Err(Validation::Limit);
        }
        document.global_rules.validate()?;
        error_pages::validate(&document.error_pages)?;
        let mut index = BTreeMap::new();
        for (i, upstream) in document.upstreams.iter_mut().enumerate() {
            upstream.health.validate()?;
            upstream.balancing.validate()?;
            if let Some(affinity) = &upstream.affinity {
                affinity.validate()?;
            }
            if !valid_id(&upstream.id) || index.insert(upstream.id.clone(), i).is_some() {
                return Err(Validation::Identifier);
            }
            if upstream.endpoints.is_empty() || upstream.endpoints.len() > 16 {
                return Err(Validation::Endpoint);
            }
            let mut addresses = BTreeSet::new();
            for endpoint in &mut upstream.endpoints {
                if !(1..=1000).contains(&endpoint.weight)
                    || endpoint.address.port() == 0
                    || !addresses.insert(endpoint.address.clone())
                {
                    return Err(Validation::Endpoint);
                }
                if let Some(address) = endpoint.address.socket() {
                    validate_address(address, context)?;
                }
                if let Some(source) = &endpoint.source {
                    source.validate(&endpoint.address)?;
                }
                match (endpoint.protocol, &mut endpoint.tls_server_name) {
                    (Protocol::Http, None) if endpoint.tls_verify => {}
                    (Protocol::Https, Some(name)) => {
                        *name = hostname(name)?;
                    }
                    _ => return Err(Validation::Endpoint),
                }
            }
            let t = &upstream.timeouts;
            if !t.valid() {
                return Err(Validation::Timeout);
            }
        }
        let mut ids = BTreeSet::new();
        for route in &mut document.routes {
            if let Some(policy) = &route.maintenance {
                policy.validate()?;
            }
            error_pages::validate(&route.error_pages)?;
            if let Some(policy) = &route.password_protect {
                policy.validate()?;
            }
            if !valid_id(&route.id) || !ids.insert(route.id.clone()) {
                return Err(Validation::Identifier);
            }
            if let Some(suffix) = route.hostname.strip_prefix("*.") {
                let suffix = hostname(suffix)?;
                if suffix.parse::<IpAddr>().is_ok() {
                    return Err(Validation::Hostname);
                }
                route.hostname = format!("*.{suffix}");
            } else {
                route.hostname = hostname(&route.hostname)?;
            }
            route.path = canonical_path(&route.path)?;
            if route.path.starts_with(password::LOGIN_PREFIX) {
                return Err(Validation::PasswordProtect);
            }
            if route.methods.len() > 16 {
                return Err(Validation::Method);
            }
            let mut methods = BTreeSet::new();
            for method in &route.methods {
                if method.len() > 32
                    || method.parse::<http::Method>().is_err()
                    || !method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
                    || !methods.insert(method)
                {
                    return Err(Validation::Method);
                }
            }
            route.methods.sort();
            traffic::validate(route)?;
            route.retry.validate()?;
            route.record_body.validate()?;
            if let Some(body) = &route.body {
                body.validate()?;
            }
            route.security_headers.validate()?;
            route.middleware.validate()?;
            if route
                .middleware
                .identity_rate_limit
                .as_ref()
                .is_some_and(|q| !q.require_identity)
                && route.access.rate_limit.is_none()
                && document.global_rules.rate_limit.is_none()
            {
                return Err(Validation::Middleware);
            }
            if route.middleware.api_schema.is_some()
                && (route.body.as_ref().is_some_and(|b| {
                    b.inspection != retry::Inspection::Full || b.max_body_bytes > 65536
                }) || route.content.as_ref().is_none_or(|c| {
                    c.media_types != ["application/json"] || !c.require_type_for_body
                }))
            {
                return Err(Validation::Middleware);
            }
            if let Some(auth) = &route.middleware.forward_auth
                && !index.contains_key(&auth.upstream)
            {
                return Err(Validation::Reference);
            }
            route.access.validate()?;
            route.admission.validate()?;
            if let Some(policy) = &mut route.waf {
                policy.validate()?;
            }
            if let Some(target) = &route.application {
                target.validate()?;
                if !route.upstream.is_empty()
                    || route.redirect.is_some()
                    || route.path != "/"
                    || route.path_match != PathMatch::Prefix
                    || route.hostname.starts_with("*.")
                    || !route.methods.is_empty()
                {
                    return Err(Validation::Application);
                }
            }
            let needs_upstream =
                route.application.is_none() && route.redirect.as_ref().is_none_or(|r| r.http_only);
            if !needs_upstream && !route.upstream.is_empty() {
                return Err(Validation::Redirect);
            }
            if needs_upstream && !index.contains_key(&route.upstream) {
                return Err(Validation::Reference);
            }
        }
        for (i, a) in document.routes.iter().enumerate() {
            for b in &document.routes[i + 1..] {
                if a.hostname == b.hostname
                    && a.path == b.path
                    && a.path_match == b.path_match
                    && ((a.methods.is_empty() && b.methods.is_empty())
                        || (!a.methods.is_empty()
                            && !b.methods.is_empty()
                            && a.methods.iter().any(|m| b.methods.contains(m))))
                {
                    return Err(Validation::Ambiguous);
                }
            }
        }
        response::validate_redirects(&document.routes)?;
        let counters = document
            .upstreams
            .iter()
            .map(|_| AtomicUsize::new(0))
            .collect();
        Ok(Self {
            password_verifiers: document.routes.iter().map(|_| None).collect(),
            version,
            prepared: None,
            applications: None,
            health: health::Health::new(&document, context.clone()),
            waf_usage: document
                .routes
                .iter()
                .map(|r| waf::Usage::new(r.waf.as_ref()))
                .collect(),
            coverage: document
                .routes
                .iter()
                .map(|_| traffic::Coverage::default())
                .collect(),
            selectors: document
                .upstreams
                .iter()
                .map(|_| balancing::Selector::default())
                .collect(),
            document,
            counters,
            upstream_index: index,
        })
    }
    pub fn route(&self, host: &str, path: &str, method: &str) -> Option<usize> {
        self.document
            .routes
            .iter()
            .enumerate()
            .filter(|(_, r)| r.matches(host, path, method))
            .max_by_key(|(_, r)| r.precedence())
            .map(|(i, _)| i)
    }
    pub fn endpoint(&self, route: usize) -> Option<(&Endpoint, &Timeouts, Arc<health::Peer>)> {
        self.endpoint_with(route, |_, _| true)
    }
    pub fn named_upstream(&self, name: &str) -> Option<usize> {
        self.upstream_index.get(name).copied()
    }
    pub fn auth_endpoint(
        &self,
        name: &str,
        allow: impl Fn(&Endpoint) -> bool,
    ) -> Option<(&Endpoint, Arc<health::Peer>)> {
        let index = self.named_upstream(name)?;
        let upstream = &self.document.upstreams[index];
        let next = self.counters[index].fetch_add(1, Ordering::Relaxed);
        for offset in 0..upstream.endpoints.len() {
            let i = (next.wrapping_add(offset)) % upstream.endpoints.len();
            let endpoint = &upstream.endpoints[i];
            if allow(endpoint)
                && let Some(peer) = self
                    .health
                    .select(index, i, next / upstream.endpoints.len())
            {
                return Some((endpoint, peer));
            }
        }
        None
    }
    pub fn endpoint_with(
        &self,
        route: usize,
        allow: impl Fn(usize, &Endpoint) -> bool,
    ) -> Option<(&Endpoint, &Timeouts, Arc<health::Peer>)> {
        self.endpoint_with_load(route, allow, |_, _| (0, 1000))
    }
    pub fn endpoint_with_load(
        &self,
        route: usize,
        allow: impl Fn(usize, &Endpoint) -> bool,
        load: impl Fn(usize, &Endpoint) -> (usize, u64),
    ) -> Option<(&Endpoint, &Timeouts, Arc<health::Peer>)> {
        let route = self.document.routes.get(route)?;
        let index = *self.upstream_index.get(&route.upstream)?;
        let upstream = &self.document.upstreams[index];
        let next = self.counters[index].fetch_add(1, Ordering::Relaxed);
        // Fixed-size local storage: strict round robin among eligible configured
        // endpoints, without overweighting a neighbor of an unhealthy endpoint.
        let mut available = [const { None }; 16];
        let mut count = 0;
        let mut candidates = [(0, 0, 0); 16];
        for (endpoint, available_peer) in available
            .iter_mut()
            .enumerate()
            .take(upstream.endpoints.len())
        {
            if !allow(endpoint, &upstream.endpoints[endpoint]) {
                continue;
            }
            if let Some(peer) = self
                .health
                .select(index, endpoint, next / upstream.endpoints.len())
            {
                *available_peer = Some(peer);
                let (active, operation_progress) = load(endpoint, &upstream.endpoints[endpoint]);
                let progress = self
                    .health
                    .recovery_progress(index, endpoint, upstream.balancing.slow_start_ms)
                    .min(operation_progress);
                let weight = if upstream.balancing.algorithm == balancing::Algorithm::RoundRobin {
                    1
                } else {
                    u64::from(upstream.endpoints[endpoint].weight)
                };
                candidates[count] = (endpoint, (weight * progress).max(1), active);
                count += 1;
            }
        }
        if count == 0 {
            return None;
        }
        let endpoint = self.selectors[index].choose(
            upstream.balancing.algorithm,
            &candidates[..count],
            next,
        )?;
        let peer = available[endpoint].take()?;
        Some((
            &upstream.endpoints[endpoint],
            route.timeouts.as_ref().unwrap_or(&upstream.timeouts),
            peer,
        ))
    }
    pub fn timeouts(&self, route: usize) -> Option<&Timeouts> {
        if let Some(timeouts) = &self.document.routes.get(route)?.timeouts {
            return Some(timeouts);
        }
        let index = self.upstream_for_route(route)?;
        Some(&self.document.upstreams[index].timeouts)
    }
    pub fn upstream_for_route(&self, route: usize) -> Option<usize> {
        self.upstream_index
            .get(&self.document.routes.get(route)?.upstream)
            .copied()
    }
}
pub struct Store(
    ArcSwap<Snapshot>,
    pub Arc<operations::Operations>,
    std::sync::Mutex<Vec<std::sync::Weak<Snapshot>>>,
);
impl Store {
    pub fn new(snapshot: Snapshot) -> Self {
        let operations = Arc::new(operations::Operations::default());
        operations.reconcile(&[&snapshot.document]);
        Self(
            ArcSwap::from_pointee(snapshot),
            operations,
            std::sync::Mutex::new(Vec::new()),
        )
    }
    pub fn load(&self) -> Arc<Snapshot> {
        self.0.load_full()
    }
    /// Only the serialized control-plane writer may publish a prepared snapshot.
    pub fn publish(&self, snapshot: Snapshot) {
        let mut retired = self.2.lock().unwrap_or_else(|e| e.into_inner());
        retired.push(Arc::downgrade(&self.load()));
        let held: Vec<_> = retired
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        retired.retain(|s| s.strong_count() > 0);
        let mut documents: Vec<_> = held.iter().map(|s| &s.document).collect();
        documents.push(&snapshot.document);
        self.1.reconcile(&documents);
        self.0.store(Arc::new(snapshot));
    }
}

#[derive(Serialize)]
pub struct Changes {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}
#[derive(Serialize)]
pub struct Diff {
    pub global_rules_changed: bool,
    pub error_pages_changed: bool,
    pub routes: Changes,
    pub upstreams: Changes,
    pub trusted_proxies_changed: bool,
}
pub fn diff(before: &Document, after: &Document) -> Diff {
    fn changes<T: PartialEq>(a: BTreeMap<&str, &T>, b: BTreeMap<&str, &T>) -> Changes {
        Changes {
            added: b
                .keys()
                .filter(|k| !a.contains_key(**k))
                .map(|k| (*k).into())
                .collect(),
            removed: a
                .keys()
                .filter(|k| !b.contains_key(**k))
                .map(|k| (*k).into())
                .collect(),
            changed: a
                .iter()
                .filter(|(k, v)| b.get(**k).is_some_and(|other| **v != *other))
                .map(|(k, _)| (*k).into())
                .collect(),
        }
    }
    Diff {
        global_rules_changed: before.global_rules != after.global_rules,
        error_pages_changed: before.error_pages != after.error_pages,
        routes: changes(
            before.routes.iter().map(|r| (r.id.as_str(), r)).collect(),
            after.routes.iter().map(|r| (r.id.as_str(), r)).collect(),
        ),
        upstreams: changes(
            before
                .upstreams
                .iter()
                .map(|r| (r.id.as_str(), r))
                .collect(),
            after.upstreams.iter().map(|r| (r.id.as_str(), r)).collect(),
        ),
        trusted_proxies_changed: before.trusted_proxies != after.trusted_proxies,
    }
}

impl Route {
    pub fn host_matches(&self, host: &str) -> bool {
        self.hostname == host
            || self.hostname.strip_prefix("*.").is_some_and(|suffix| {
                host.strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
            })
    }
    pub fn path_matches(&self, path: &str) -> bool {
        self.path == path
            || (self.path_match == PathMatch::Prefix
                && path.starts_with(&self.path)
                && (self.path.ends_with('/')
                    || path.as_bytes().get(self.path.len()) == Some(&b'/')))
    }
    pub fn matches(&self, host: &str, path: &str, method: &str) -> bool {
        self.host_matches(host)
            && self.path_matches(path)
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == method))
    }
    pub fn precedence(&self) -> (bool, usize, bool, usize, bool) {
        (
            !self.hostname.starts_with("*."),
            self.hostname.len(),
            self.path_match == PathMatch::Exact,
            self.path.len(),
            !self.methods.is_empty(),
        )
    }
}

pub mod api_schema;

pub mod abuse;
