//! Explicit endpoint checks in the gateway's namespace, outside the proxy hot path.
//! No redirects, body capture, ambient proxies, credentials or protocol guessing.
use hickory_resolver::{TokioAsyncResolver, system_conf::read_system_conf};
use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509VerifyResult},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
};

const MAX_HEADERS: usize = 16 * 1024;
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub tls_server_name: Option<String>,
    #[serde(default = "openwaf_config::default_tls_verify")]
    pub tls_verify: bool,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidEndpoint,
    Busy,
    DnsFailed,
    TooManyAddresses,
    ForbiddenEndpoint,
    TcpRefused,
    TcpFailed,
    DeadlineExceeded,
    TlsVerificationFailed,
    TlsFailed,
    NotHttp,
    HeadersTooLarge,
    HttpIo,
    UnexpectedInformationalResponse,
}
impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::Busy => "busy",
            Self::DnsFailed => "dns_failed",
            Self::TooManyAddresses => "too_many_addresses",
            Self::ForbiddenEndpoint => "forbidden_endpoint",
            Self::TcpRefused => "tcp_refused",
            Self::TcpFailed => "tcp_failed",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::TlsVerificationFailed => "tls_verification_failed",
            Self::TlsFailed => "tls_failed",
            Self::NotHttp => "not_http",
            Self::HeadersTooLarge => "headers_too_large",
            Self::HttpIo => "http_io",
            Self::UnexpectedInformationalResponse => "unexpected_informational_response",
        }
    }
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    NotRun,
    Passed,
    Failed,
}
impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}
#[derive(Serialize)]
pub struct Step {
    pub state: State,
    pub latency_ms: Option<u64>,
    pub error: Option<ErrorCode>,
}
impl Default for Step {
    fn default() -> Self {
        Self {
            state: State::NotRun,
            latency_ms: None,
            error: None,
        }
    }
}
impl Step {
    fn finish(&mut self, start: Instant, result: Result<(), ErrorCode>) {
        self.latency_ms = Some(millis(start));
        match result {
            Ok(()) => self.state = State::Passed,
            Err(error) => {
                self.state = State::Failed;
                self.error = Some(error);
            }
        }
    }
}
#[derive(Serialize, Default)]
pub struct Report {
    pub available: bool,
    pub error: Option<ErrorCode>,
    pub endpoint: Option<SocketAddr>,
    pub dns: Step,
    pub tcp: Step,
    pub tls: Step,
    pub http: Step,
    pub http_status: Option<u16>,
    pub latency_ms: u64,
}
fn millis(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}
fn valid_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !ip.is_unspecified() && !ip.is_multicast();
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
fn validate(endpoint: &Endpoint) -> Result<(), ErrorCode> {
    if endpoint.port == 0
        || !valid_host(&endpoint.host)
        || endpoint
            .tls_server_name
            .as_ref()
            .is_some_and(|name| !valid_host(name))
        || (endpoint.protocol == Protocol::Http
            && (endpoint.tls_server_name.is_some() || !endpoint.tls_verify))
    {
        return Err(ErrorCode::InvalidEndpoint);
    }
    Ok(())
}
fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        other => other,
    }
}
pub struct ProbeService {
    resolver: TokioAsyncResolver,
    tls: SslConnector,
    permits: Arc<Semaphore>,
    denied: Vec<SocketAddr>,
    deadline: Duration,
    context: Option<openwaf_config::Context>,
}
impl ProbeService {
    /// Construct during startup, never on a request's hot path. Trust additions
    /// are operator configuration; callers cannot disable certificate verification.
    pub fn new(denied: Vec<SocketAddr>, ca: Option<&Path>) -> anyhow::Result<Self> {
        let (config, mut options) = read_system_conf()?;
        options.cache_size = 128;
        options.attempts = 1;
        options.timeout = Duration::from_secs(2);
        let resolver = TokioAsyncResolver::tokio(config, options);
        Self::with_resolver(resolver, denied, ca)
    }
    pub fn with_resolver(
        resolver: TokioAsyncResolver,
        denied: Vec<SocketAddr>,
        ca: Option<&Path>,
    ) -> anyhow::Result<Self> {
        Self::with_capacity(resolver, denied, ca, 4)
    }
    pub(crate) fn with_capacity(
        resolver: TokioAsyncResolver,
        denied: Vec<SocketAddr>,
        ca: Option<&Path>,
        capacity: usize,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=16).contains(&capacity), "invalid probe capacity");
        anyhow::ensure!(denied.len() <= 128, "too many probe exclusions");
        let mut tls = SslConnector::builder(SslMethod::tls_client())?;
        tls.set_verify(SslVerifyMode::PEER);
        tls.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        tls.set_alpn_protos(b"\x08http/1.1")?;
        if let Some(path) = ca {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            anyhow::ensure!(
                file.metadata()?.is_file() && file.metadata()?.len() <= 1024 * 1024,
                "probe trust file must be a bounded regular file"
            );
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 1024 * 1024, "probe trust file exceeds limit");
            let certificates = X509::stack_from_pem(&bytes)?;
            anyhow::ensure!(
                !certificates.is_empty() && certificates.len() <= 128,
                "invalid probe trust bundle"
            );
            for cert in certificates {
                tls.cert_store_mut().add_cert(cert)?;
            }
        }
        Ok(Self {
            resolver,
            tls: tls.build(),
            permits: Arc::new(Semaphore::new(capacity)),
            denied,
            deadline: Duration::from_secs(3),
            context: None,
        })
    }
    pub fn with_context(mut self, context: openwaf_config::Context) -> Self {
        self.context = Some(context);
        self
    }
    pub async fn test(&self, endpoint: Endpoint) -> Report {
        let start = Instant::now();
        let mut report = Report::default();
        let result = async {
            validate(&endpoint)?;
            let _permit = self.permits.try_acquire().map_err(|_| ErrorCode::Busy)?;
            self.check(&endpoint, &mut report, None, None).await
        }
        .await;
        report.available = result.is_ok();
        report.error = result.err();
        report.latency_ms = millis(start);
        report
    }
    /// Probe an already resolved, validated address while preserving HTTP Host and TLS SNI.
    /// The caller owns DNS TTL and must validate the entire DNS answer before use.
    pub async fn test_at(&self, endpoint: Endpoint, address: SocketAddr) -> Report {
        self.test_at_request(endpoint, address, None).await
    }
    pub(crate) async fn health_at(
        &self,
        endpoint: Endpoint,
        address: SocketAddr,
        settings: &openwaf_config::health::Settings,
    ) -> Report {
        self.test_at_request(endpoint, address, Some(settings))
            .await
    }
    async fn test_at_request(
        &self,
        endpoint: Endpoint,
        address: SocketAddr,
        settings: Option<&openwaf_config::health::Settings>,
    ) -> Report {
        let start = Instant::now();
        let mut report = Report::default();
        let result = async {
            validate(&endpoint)?;
            if let Some(settings) = settings {
                settings
                    .clone()
                    .validate()
                    .map_err(|_| ErrorCode::InvalidEndpoint)?;
            }
            if endpoint.port != address.port() {
                return Err(ErrorCode::InvalidEndpoint);
            }
            let _permit = self.permits.try_acquire().map_err(|_| ErrorCode::Busy)?;
            self.check(&endpoint, &mut report, Some(address), settings)
                .await
        }
        .await;
        report.available = result.is_ok();
        report.error = result.err();
        report.latency_ms = millis(start);
        report
    }
    async fn check(
        &self,
        endpoint: &Endpoint,
        report: &mut Report,
        resolved: Option<SocketAddr>,
        settings: Option<&openwaf_config::health::Settings>,
    ) -> Result<(), ErrorCode> {
        let deadline = tokio::time::Instant::now()
            + settings.map_or(self.deadline, |s| Duration::from_millis(s.timeout_ms));
        let start = Instant::now();
        let resolve = async {
            let ips = if let Some(address) = resolved {
                vec![address.ip()]
            } else if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
                vec![ip]
            } else {
                let response = self
                    .resolver
                    .lookup_ip(endpoint.host.as_str())
                    .await
                    .map_err(|_| ErrorCode::DnsFailed)?;
                let mut ips = Vec::new();
                for ip in response.iter() {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                    if ips.len() > 16 {
                        return Err(ErrorCode::TooManyAddresses);
                    }
                }
                ips
            };
            if ips.is_empty() {
                return Err(ErrorCode::DnsFailed);
            }
            let addresses: Vec<_> = ips
                .into_iter()
                .map(|ip| SocketAddr::new(normalized(ip), endpoint.port))
                .collect();
            // Validate the entire answer before connecting, including DNS aliases
            // and mapped IPv4. Never silently select an alternative to a self loop.
            if addresses.iter().any(|addr| {
                addr.ip().is_unspecified()
                    || addr.ip().is_multicast()
                    || self.context.as_ref().is_some_and(|context| {
                        openwaf_config::validate_address(*addr, context).is_err()
                    })
                    || self.denied.iter().any(|denied| {
                        denied.port() == addr.port()
                            && (denied.ip().is_unspecified()
                                || normalized(denied.ip()) == addr.ip())
                    })
            }) {
                return Err(ErrorCode::ForbiddenEndpoint);
            }
            Ok(addresses)
        };
        let resolved = until(deadline, resolve).await;
        report
            .dns
            .finish(start, resolved.as_ref().map(|_| ()).map_err(|e| *e));
        let addresses = resolved?;
        let start = Instant::now();
        let connected = until(deadline, async {
            let mut last = ErrorCode::TcpFailed;
            for address in addresses {
                report.endpoint = Some(address);
                match TcpStream::connect(address).await {
                    Ok(stream) => return Ok((stream, address)),
                    Err(error) => {
                        last = if error.kind() == std::io::ErrorKind::ConnectionRefused {
                            ErrorCode::TcpRefused
                        } else {
                            ErrorCode::TcpFailed
                        }
                    }
                }
            }
            Err(last)
        })
        .await;
        report
            .tcp
            .finish(start, connected.as_ref().map(|_| ()).map_err(|e| *e));
        let (stream, address) = connected?;
        report.endpoint = Some(address);
        let name = endpoint
            .tls_server_name
            .as_deref()
            .unwrap_or(&endpoint.host);
        let name = name.strip_suffix('.').unwrap_or(name);
        if endpoint.protocol == Protocol::Https {
            let start = Instant::now();
            let handshake = until(deadline, async {
                let ssl = self
                    .tls
                    .configure()
                    .and_then(|mut config| {
                        config.set_verify_hostname(endpoint.tls_verify);
                        if !endpoint.tls_verify {
                            config.set_verify(openssl::ssl::SslVerifyMode::NONE);
                        }
                        config.into_ssl(name)
                    })
                    .map_err(|_| ErrorCode::TlsFailed)?;
                let mut stream =
                    tokio_openssl::SslStream::new(ssl, stream).map_err(|_| ErrorCode::TlsFailed)?;
                if Pin::new(&mut stream).connect().await.is_err() {
                    return Err(if stream.ssl().verify_result() != X509VerifyResult::OK {
                        ErrorCode::TlsVerificationFailed
                    } else {
                        ErrorCode::TlsFailed
                    });
                }
                Ok(stream)
            })
            .await;
            report
                .tls
                .finish(start, handshake.as_ref().map(|_| ()).map_err(|e| *e));
            let mut stream = handshake?;
            self.http(&mut stream, name, endpoint.port, deadline, report, settings)
                .await
        } else {
            let mut stream = stream;
            self.http(&mut stream, name, endpoint.port, deadline, report, settings)
                .await
        }
    }
    async fn http<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        name: &str,
        port: u16,
        deadline: tokio::time::Instant,
        report: &mut Report,
        settings: Option<&openwaf_config::health::Settings>,
    ) -> Result<(), ErrorCode> {
        let start = Instant::now();
        let result = until(deadline, http(stream, name, port, settings)).await;
        report
            .http
            .finish(start, result.as_ref().map(|_| ()).map_err(|e| *e));
        report.http_status = result.as_ref().ok().copied();
        result.map(|_| ())
    }
}
async fn until<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = Result<T, ErrorCode>>,
) -> Result<T, ErrorCode> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ErrorCode::DeadlineExceeded)?
}
async fn http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    name: &str,
    port: u16,
    settings: Option<&openwaf_config::health::Settings>,
) -> Result<u16, ErrorCode> {
    let host = if name.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{name}]")
    } else {
        name.to_owned()
    };
    let default_host = format!("{host}:{port}");
    let host = settings
        .and_then(|s| s.host.as_deref())
        .unwrap_or(&default_host);
    let path = settings.map_or("/", |s| s.path.as_str());
    let method = settings.map_or("HEAD", |s| s.method.as_str());
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OpenWAF-Probe/1\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ErrorCode::HttpIo)?;
    let mut input = Vec::new();
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&input) {
            Ok(httparse::Status::Complete(_)) => {
                let status = response.code.ok_or(ErrorCode::NotHttp)?;
                return if (200..=599).contains(&status) {
                    Ok(status)
                } else {
                    Err(ErrorCode::UnexpectedInformationalResponse)
                };
            }
            Err(httparse::Error::TooManyHeaders) => return Err(ErrorCode::HeadersTooLarge),
            Err(_) => return Err(ErrorCode::NotHttp),
            Ok(httparse::Status::Partial) => {}
        }
        if input.len() >= MAX_HEADERS {
            return Err(ErrorCode::HeadersTooLarge);
        }
        let mut chunk = [0; 1024];
        let limit = chunk.len().min(MAX_HEADERS - input.len());
        let size = stream
            .read(&mut chunk[..limit])
            .await
            .map_err(|_| ErrorCode::HttpIo)?;
        if size == 0 {
            return Err(ErrorCode::NotHttp);
        }
        input.extend_from_slice(&chunk[..size]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use tokio::net::TcpListener;
    fn service(denied: Vec<SocketAddr>) -> ProbeService {
        ProbeService::with_resolver(
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
            denied,
            None,
        )
        .unwrap()
    }
    fn endpoint(address: SocketAddr) -> Endpoint {
        Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
            protocol: Protocol::Http,
            tls_server_name: None,
            tls_verify: true,
        }
    }
    #[test]
    fn rejects_ambiguous_or_injectable_targets() {
        let mut value = endpoint("127.0.0.1:80".parse().unwrap());
        for host in [
            "",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "http://localhost",
            "user@localhost",
            "a/b",
            "a\r\nHost:x",
            "[::1]",
            "-web",
            "a..b",
        ] {
            value.host = host.into();
            assert_eq!(validate(&value), Err(ErrorCode::InvalidEndpoint), "{host}");
        }
        for host in ["localhost", "web", "web.test.", "127.0.0.1", "::1"] {
            value.host = host.into();
            assert!(validate(&value).is_ok());
        }
        value.port = 0;
        assert_eq!(validate(&value), Err(ErrorCode::InvalidEndpoint));
    }
    #[tokio::test]
    async fn rejects_mapped_and_wildcard_self_loops_before_connect() {
        let service = service(vec![
            "127.0.0.1:8080".parse().unwrap(),
            "[::]:9090".parse().unwrap(),
        ]);
        for address in [
            "[::ffff:127.0.0.1]:8080",
            "127.0.0.1:9090",
            "[::1]:9090",
            "[::ffff:0.0.0.0]:80",
        ] {
            let report = service.test(endpoint(address.parse().unwrap())).await;
            assert_eq!(report.error, Some(ErrorCode::ForbiddenEndpoint));
            assert!(matches!(report.tcp.state, State::NotRun));
        }
    }
    #[tokio::test]
    async fn bounded_admission_and_cancellation_release_socket_and_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = endpoint(listener.local_addr().unwrap());
        let service = Arc::new(service(Vec::new()));
        let mut jobs = tokio::task::JoinSet::new();
        let mut sockets = Vec::new();
        for _ in 0..4 {
            let service = service.clone();
            let target = target.clone();
            jobs.spawn(async move { service.test(target).await });
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            sockets.push(socket);
        }
        assert_eq!(service.test(target).await.error, Some(ErrorCode::Busy));
        jobs.abort_all();
        while jobs.join_next().await.is_some() {}
        assert_eq!(service.permits.available_permits(), 4);
        for mut socket in sockets {
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), socket.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
        }
    }
    #[tokio::test]
    async fn slow_http_has_total_deadline_and_keeps_tcp_result() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = endpoint(listener.local_addr().unwrap());
        let mut service = service(Vec::new());
        service.deadline = Duration::from_millis(100);
        let result = service.test(target).await;
        assert_eq!(result.error, Some(ErrorCode::DeadlineExceeded));
        assert!(matches!(result.tcp.state, State::Passed));
        assert!(matches!(result.http.state, State::Failed));
        assert_eq!(service.permits.available_permits(), 4);
    }
    #[tokio::test]
    async fn dns_cache_expires_and_connection_uses_new_address() {
        use hickory_resolver::{
            config::{LookupIpStrategy, NameServerConfigGroup},
            proto::{
                op::{Message, MessageType},
                rr::{
                    RData, Record, RecordType,
                    rdata::{A, AAAA},
                },
            },
        };
        use std::{
            net::{Ipv4Addr, Ipv6Addr},
            sync::atomic::{AtomicU8, AtomicUsize, Ordering},
        };
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_port = dns.local_addr().unwrap().port();
        let last_octet = Arc::new(AtomicU8::new(1));
        let queries = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        let value = last_octet.clone();
        let requests = queries.clone();
        tasks.spawn(async move {
            let mut input = [0; 512];
            loop {
                let (size, peer) = dns.recv_from(&mut input).await.unwrap();
                let query = Message::from_vec(&input[..size]).unwrap();
                requests.fetch_add(1, Ordering::SeqCst);
                let mut response = Message::new();
                response
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_available(true);
                for question in query.queries() {
                    response.add_query(question.clone());
                    if question.query_type() == RecordType::A && value.load(Ordering::SeqCst) == 1 {
                        response.add_answer(Record::from_rdata(
                            question.name().clone(),
                            1,
                            RData::A(A(Ipv4Addr::LOCALHOST)),
                        ));
                    }
                }
                if value.load(Ordering::SeqCst) == 2 {
                    for question in query.queries() {
                        if question.query_type() == RecordType::AAAA {
                            response.add_answer(Record::from_rdata(
                                question.name().clone(),
                                1,
                                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                            ));
                        }
                    }
                }
                dns.send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = first.local_addr().unwrap().port();
        let second = TcpListener::bind(("::1", port)).await.unwrap();
        for listener in [first, second] {
            tasks.spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut input = [0; 1024];
                    assert!(stream.read(&mut input).await.unwrap() > 0);
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                }
            });
        }
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            NameServerConfigGroup::from_ips_clear(&["127.0.0.1".parse().unwrap()], dns_port, true),
        );
        let mut options = ResolverOpts::default();
        options.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        options.use_hosts_file = false;
        options.attempts = 1;
        let mut service = ProbeService::with_resolver(
            TokioAsyncResolver::tokio(config, options),
            Vec::new(),
            None,
        )
        .unwrap();
        let target = Endpoint {
            host: "changing.example.test.".into(),
            port,
            protocol: Protocol::Http,
            tls_server_name: None,
            tls_verify: true,
        };
        let initial = service.test(target.clone()).await;
        assert!(initial.available);
        assert_eq!(initial.endpoint.unwrap().ip().to_string(), "127.0.0.1");
        last_octet.store(2, Ordering::SeqCst);
        assert_eq!(
            service.test(target.clone()).await.endpoint,
            initial.endpoint
        );
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let updated = service.test(target.clone()).await;
        assert!(updated.available);
        assert_eq!(updated.endpoint.unwrap().ip().to_string(), "::1");
        assert!(queries.load(Ordering::SeqCst) >= 2);
        service.denied.push(updated.endpoint.unwrap());
        assert_eq!(
            service.test(target).await.error,
            Some(ErrorCode::ForbiddenEndpoint)
        );
        tasks.shutdown().await;
    }
}
