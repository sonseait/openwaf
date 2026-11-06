//! Bounded Pingora/WAF gateway with optional managed routing and upstream health.
#![forbid(unsafe_code)]
mod admin;
mod affinity;
mod application_route;
mod challenge_route;
mod decision_trace;
mod lifetime;
mod listener;
mod maintenance_route;
mod password_route;
mod replay;
mod request_id;
mod retry;
mod shadow;
mod simulator;
mod target;
mod tls_reload;
mod waf_policy;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use openwaf_waf::{Decision, MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADERS, Mode, Pool, Request};
use pingora::{http::RequestHeader, prelude::*, server::RunArgs};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

struct Gateway {
    correlator: openwaf_security::correlation::Correlator,
    abuse: Arc<openwaf_security::abuse::Service>,
    body_recorder: Arc<openwaf_storage::bodies::Service>,
    challenge_gate: openwaf_gateway::challenge::Gate,
    password_gate: openwaf_gateway::password_protect::Gate,
    forward_auth: openwaf_gateway::forward_auth::Client,
    affinity_key: affinity::SignerKey,
    shadow: Arc<shadow::Service>,
    replay_budget: Arc<replay::Budget>,
    retry_slots: Arc<openwaf_gateway::admission::Gate>,
    telemetry: Arc<openwaf_telemetry::Hub>,
    admission: Arc<openwaf_gateway::admission::Node>,
    response_write_failures: Arc<std::sync::atomic::AtomicU64>,
    geoip: Option<openwaf_security::traffic::CountryDb>,
    principal_limiter: Arc<openwaf_security::principal::Limiter>,
    rate_limiter: Arc<openwaf_security::traffic::Limiter>,
    global_rate_limiter: Arc<openwaf_security::traffic::Limiter>,
    ddos: Arc<openwaf_security::ddos::Protection>,
    upstream_ca: Option<Arc<pingora::protocols::tls::CaType>>,
    config: Option<Arc<openwaf_config::Store>>,
    health_requests: Arc<openwaf_config::requests::Requests>,
    tls: bool,
    pool: Arc<Pool>,
    upstream: SocketAddr,
    listener: SocketAddr,
    mode: Mode,
    crowdsec: Option<Arc<openwaf_security::Store>>,
}

#[derive(Default)]
struct RequestContext {
    correlation: Option<String>,
    correlation_cookie: Option<String>,
    body_recording: Option<openwaf_storage::bodies::Recording>,
    body_recording_marker: Option<openwaf_storage::bodies::Record>,
    decision_trace: decision_trace::Trace,
    password_endpoint: bool,
    metadata: openwaf_gateway::request_details::Capture,
    location: openwaf_gateway::error_pages::Location,
    cors: Option<openwaf_config::middleware::CorsResponse>,
    abuse_observer: Option<Arc<openwaf_security::abuse::Service>>,
    upstream_status: u16,
    signals: Vec<openwaf_gateway::security_signals::Signal>,
    auth_identity: http::HeaderMap,
    auth_headers: http::HeaderMap,
    rewritten_uri: Option<http::Uri>,
    request_id: String,
    lifetime_outcome: Arc<std::sync::atomic::AtomicU8>,
    response_progress: Arc<std::sync::atomic::AtomicU16>,
    effective_timeouts: Option<serde_json::Value>,
    failure: Option<&'static str>,
    endpoint_lease: Option<openwaf_config::operations::Lease>,
    affinity_cookie: Option<String>,
    retry: retry::State,
    body_limit: u64,
    streaming: bool,
    body_inspection: &'static str,
    profile: Option<openwaf_config::traffic::Profile>,
    security_layer: &'static str,
    waf_report: Option<openwaf_waf::Report>,
    waf_enforced: bool,
    waf_observed_at_unix_ms: u64,
    telemetry: Option<openwaf_telemetry::Request>,
    _health_lease: Option<openwaf_config::requests::Lease>,
    _auth_health_lease: Option<openwaf_config::requests::Lease>,
    _permit: Option<openwaf_gateway::admission::Lease>,
    snapshot: Option<Arc<openwaf_config::Snapshot>>,
    route: Option<usize>,
    client: Option<SocketAddr>,
    host: String,
    peer: Option<Arc<openwaf_config::health::Peer>>,
    passive_health: openwaf_gateway::passive_health::Observation,
}

impl RequestContext {
    fn finish_body_recording(&mut self, request_complete: bool, response_complete: bool) {
        if let Some(recording) = self.body_recording.take() {
            self.body_recording_marker =
                Some(recording.finish(request_complete, response_complete));
        }
    }
    fn record_response_header(&mut self, header: &pingora::http::ResponseHeader, empty: bool) {
        if let Some(recording) = &mut self.body_recording {
            recording.response.headers(&header.headers, empty);
        }
    }
    fn record_response_chunk(&mut self, body: &[u8], end: bool) {
        if let Some(recording) = &mut self.body_recording {
            recording.response.push(body, end);
        }
    }
    fn signal(&mut self, source: &'static str, reason: &'static str, action: &'static str) {
        if self.signals.len() < 17 {
            self.signals
                .push(openwaf_gateway::security_signals::Signal::outcome(
                    source, reason, action,
                ));
        }
    }
    fn checked(&mut self, stage: &'static str, result: &'static str) {
        self.decision_trace.checked(stage, result);
    }
    fn details(&self, outcome: &str, committed: bool, observed_status: u16) -> String {
        openwaf_gateway::request_details::serialize(serde_json::json!({
            "schema_version": openwaf_gateway::request_details::SCHEMA_VERSION,
            "decision_trace": self.decision_trace,
            "metadata": self.metadata,
            "body_recording": self.body_recording_marker,
            "outcome": outcome,
            "response_committed": committed,
            "response_status_observed": observed_status,
            "effective_timeouts": self.effective_timeouts,
            "route_id": self.snapshot.as_ref().zip(self.route).map(|(s,r)| &s.document.routes[r].id),
            "application": self.snapshot.as_ref().zip(self.route).and_then(|(s,r)| s.document.routes[r].application.as_ref()),
            "security_layer": self.security_layer,
            "body_inspection": self.body_inspection,
            "profile": self.profile,
            "waf": self.waf_report,
            "security_signals": openwaf_gateway::security_signals::Signals::from_waf(
                self.waf_report.as_ref(), self.waf_enforced, self.body_inspection,
                self.waf_observed_at_unix_ms,
            ).with_outcomes(&self.signals, openwaf_telemetry::now_ms()),
            "attempts": self.retry.attempts,
            "retry_disabled_reason": self.retry.disabled_reason,
            "replay_disabled_reason": self.retry.capture.reason(),
        }))
    }
}

#[cfg(test)]
mod signal_details_tests;

impl Drop for RequestContext {
    fn drop(&mut self) {
        self.finish_body_recording(false, false);
        if let Some((snapshot, route)) = self.snapshot.as_ref().zip(self.route) {
            snapshot.coverage[route].record(self.body_inspection);
        }
        if let Some(request) = &self.telemetry {
            request.security(
                self.body_inspection,
                self.waf_report
                    .as_ref()
                    .is_some_and(|r| r.decision == Decision::Block),
                self.waf_report.as_ref().map_or(0, |r| r.findings.len()),
                self.waf_report.as_ref().is_some_and(|r| r.truncated),
            );
        }
        if self.telemetry.is_some() {
            if let Some(observer) = &self.abuse_observer
                && self
                    .snapshot
                    .as_ref()
                    .zip(self.route)
                    .is_some_and(|(s, r)| s.document.routes[r].middleware.detectors.is_some())
            {
                observer.observation_lost();
            }
            self.decision_trace.stop("interrupted");
            let reason = lifetime::reason(&self.lifetime_outcome);
            self.retry.disabled_reason = Some(reason);
            if let Some(attempt) = self.retry.attempts.last_mut() {
                attempt.duration_ms = self.retry.started.elapsed().as_millis() as u64;
            }
            let status = self
                .response_progress
                .load(std::sync::atomic::Ordering::Acquire);
            let details = self.details(reason, status != 0, status);
            if let Some(request) = &mut self.telemetry {
                request.request_id = self.request_id.clone();
                request.details = details;
                request.config_version = self.snapshot.as_ref().map_or(0, |s| s.version);
                request.route_index = self.route;
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = RequestContext;
    fn new_ctx(&self) -> Self::CTX {
        let mut context = RequestContext::default();
        context.abuse_observer = Some(self.abuse.clone());
        context
    }

    fn persist_connection_context(
        &self,
        _session: &Session,
        _ctx: &RequestContext,
    ) -> Option<Box<dyn std::any::Any + Send + Sync>> {
        Some(Box::new(lifetime::Reused))
    }

    fn request_summary(&self, _session: &Session, ctx: &RequestContext) -> String {
        format!(
            "OpenWAF request config_version={}",
            ctx.snapshot.as_ref().map_or(0, |s| s.version)
        )
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        ctx.lifetime_outcome = lifetime::outcome();
        ctx.response_progress = session.response_progress();
        session.as_mut().reject_trailers();
        ctx.body_inspection = "not_inspected";
        ctx.request_id = request_id::generate()
            .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
        let header = session.req_header();
        ctx.metadata = openwaf_gateway::request_details::Capture::new(
            &header.method,
            &header.uri,
            header.version,
            &header.headers,
            self.tls,
            session
                .client_addr()
                .and_then(|addr| addr.as_inet())
                .copied(),
        );
        ctx.metadata.request.body_read_complete = session.as_mut().is_body_done();
        if let Some(tls) = session
            .as_ref()
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
        {
            ctx.metadata.tls(&tls.version, &tls.cipher);
        }
        session
            .req_header_mut()
            .insert_header("x-request-id", &ctx.request_id)?;
        ctx.telemetry = Some(
            self.telemetry.start_with_agent(
                session.req_header().method.as_str(),
                session
                    .req_header()
                    .headers
                    .get("user-agent")
                    .map(|v| v.as_bytes()),
            ),
        );
        ctx.snapshot = self.config.as_ref().map(|store| store.load());
        ctx.decision_trace.begin("framing");
        ctx.security_layer = "framing";
        if session.req_header().version != pingora::http::Version::HTTP_2
            && let Err(status) = openwaf_config::traffic::raw_framing(&session.as_ref().to_h1_raw())
        {
            return self.reject(session, ctx, status).await;
        }
        if let Err(status) = openwaf_config::traffic::framing(&session.req_header().headers) {
            return self.reject(session, ctx, status).await;
        }
        ctx.checked("framing", "passed");
        ctx.decision_trace.begin("routing");
        ctx.security_layer = "routing";
        let peer = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .copied();
        ctx.client = peer.filter(|_| self.config.is_none());
        if let Some(client) = ctx.client {
            ctx.metadata.client.ip = Some(openwaf_config::normalized_ip(client.ip()));
            ctx.metadata.client.ip_source = "socket";
        }
        if session.req_header().method == "CONNECT" {
            return self.reject(session, ctx, 405).await;
        }
        let Some(host) = target::prepare(session.req_header_mut(), self.tls) else {
            return self.reject(session, ctx, 400).await;
        };
        ctx.metadata.request.host = Some(host.clone());
        self.telemetry.window.observe(
            &host,
            session.req_header().uri.path(),
            openwaf_telemetry::now_ms(),
        );
        if let Some(request) = &mut ctx.telemetry {
            request.host(&host);
        }
        // Connection nominations must not erase rebuilt identity/loop fields
        // when Pingora applies its hop-by-hop header policy downstream.
        for value in session.req_header().headers.get_all("connection") {
            let Ok(value) = value.to_str() else {
                return self.reject(session, ctx, 400).await;
            };
            if value.split(',').any(|token| {
                let name = token.trim().to_ascii_lowercase();
                name.starts_with("x-forwarded-")
                    || ["forwarded", "x-real-ip", "x-openwaf-hop", "x-request-id"]
                        .contains(&name.as_str())
            }) {
                return self.reject(session, ctx, 400).await;
            }
        }
        if let Some(snapshot) = ctx.snapshot.clone() {
            if session.req_header().headers.contains_key("x-openwaf-hop") {
                return self.reject(session, ctx, 508).await;
            }
            let header = session.req_header();
            let path = openwaf_config::canonical_path(header.uri.path());
            let (Ok(path), Some(peer)) = (path, peer) else {
                return self.reject(session, ctx, 400).await;
            };
            if header.headers.get_all("x-forwarded-for").iter().count() > 1 {
                return self.reject(session, ctx, 400).await;
            }
            let forwarded = match header
                .headers
                .get("x-forwarded-for")
                .map(|v| v.to_str())
                .transpose()
            {
                Ok(value) => value,
                Err(_) => return self.reject(session, ctx, 400).await,
            };
            let client = match openwaf_config::headers::client_ip(
                peer.ip(),
                forwarded,
                &snapshot.document.trusted_proxies,
            ) {
                Ok(client) => client,
                Err(_) => return self.reject(session, ctx, 400).await,
            };
            ctx.client = Some(SocketAddr::new(client, peer.port()));
            ctx.metadata.client.ip = Some(client);
            ctx.metadata.client.ip_source = if forwarded.is_some()
                && snapshot
                    .document
                    .trusted_proxies
                    .iter()
                    .any(|network| network.contains(&openwaf_config::normalized_ip(peer.ip())))
            {
                "trusted_proxy"
            } else {
                "socket"
            };
            self.observe_country(ctx, client);
            let preflight_method =
                if header.method == "OPTIONS" && header.headers.contains_key("origin") {
                    match openwaf_config::middleware::single(
                        &header.headers,
                        "access-control-request-method",
                    ) {
                        Ok(method) => method,
                        Err(status) => return self.reject(session, ctx, status).await,
                    }
                } else {
                    None
                };
            let cors_route = preflight_method
                .and_then(|method| snapshot.route(&host, &path, method))
                .filter(|r| snapshot.document.routes[*r].middleware.cors.is_some());
            ctx.password_endpoint = path.starts_with(openwaf_gateway::password_protect::PREFIX);
            let local_route = path
                .strip_prefix(openwaf_gateway::password_protect::PREFIX)
                .and_then(|id| {
                    snapshot.document.routes.iter().position(|r| {
                        r.id == id && r.host_matches(&host) && r.password_protect.is_some()
                    })
                });
            let Some(route) = (if ctx.password_endpoint {
                local_route
            } else {
                cors_route.or_else(|| snapshot.route(&host, &path, header.method.as_str()))
            }) else {
                return self.reject(session, ctx, 404).await;
            };
            ctx.route = Some(route);
            if let Some(request) = &mut ctx.telemetry {
                request.route(&snapshot.document.routes[route].id);
            }
            let policy = &snapshot.document.routes[route].record_body;
            let mut recording = self.body_recorder.begin(
                ctx.request_id.clone(),
                policy.request_enabled,
                policy.response_enabled,
                policy.query_enabled,
                policy.redact_fields.clone(),
            );
            recording.query.query(session.req_header().uri.query());
            // Internal password login payloads contain credentials; never capture them.
            let request_empty = session.as_mut().is_body_empty();
            recording
                .request
                .headers(&session.req_header().headers, request_empty);
            if ctx.password_endpoint {
                recording.request.suppress("internal_authentication");
            }
            ctx.body_recording = Some(recording);
            let middleware = &snapshot.document.routes[route].middleware;
            if session
                .req_header()
                .headers
                .get_all("connection")
                .iter()
                .any(|value| {
                    value.to_str().is_ok_and(|value| {
                        value.split(',').any(|name| {
                            let name = name.trim().to_ascii_lowercase();
                            middleware
                                .forward_auth
                                .as_ref()
                                .is_some_and(|auth| auth.response_headers.contains(&name))
                                || middleware
                                    .request_headers
                                    .set
                                    .iter()
                                    .any(|header| header.name == name)
                        })
                    })
                })
            {
                return self.reject(session, ctx, 400).await;
            }
            if !snapshot.document.routes[route].upstream.is_empty()
                && snapshot.document.routes[route].maintenance.is_none()
            {
                ctx._health_lease = match self.health_requests.track(&snapshot, route) {
                    Some(lease) => Some(lease),
                    None => return self.reject(session, ctx, 503).await,
                };
            }
            if let Some(auth) = snapshot.document.routes[route]
                .middleware
                .forward_auth
                .as_ref()
                .filter(|_| snapshot.document.routes[route].maintenance.is_none())
            {
                ctx._auth_health_lease = snapshot
                    .named_upstream(&auth.upstream)
                    .and_then(|u| self.health_requests.track_upstream(&snapshot, u));
                if ctx._auth_health_lease.is_none() {
                    return self.reject(session, ctx, 503).await;
                }
                // Do not let a client identity reach WAF, auth service or application.
                for name in &auth.response_headers {
                    session.req_header_mut().remove_header(name);
                }
            }
            ctx.profile = snapshot.document.routes[route].profile.clone();
            ctx.route = Some(route);
            ctx.snapshot = Some(snapshot);
            ctx.client = Some(SocketAddr::new(client, peer.port()));
            ctx.host = host;
            if ctx
                .snapshot
                .as_ref()
                .is_some_and(|s| s.document.routes[route].middleware.detectors.is_some())
                && self.tls
            {
                let now = openwaf_telemetry::now_ms() / 1000;
                let tokens: Vec<_> = session
                    .req_header()
                    .headers
                    .get_all("cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(';'))
                    .filter_map(|v| v.trim().split_once('='))
                    .filter(|(name, _)| *name == openwaf_security::correlation::COOKIE)
                    .map(|(_, value)| value)
                    .take(2)
                    .collect();
                let valid = if tokens.len() == 1 {
                    self.correlator.cookie(&ctx.host, tokens[0], now)
                } else {
                    None
                };
                if let Some(key) = valid {
                    ctx.correlation = Some(format!("session:{key}"));
                } else if let Some(token) = self.correlator.issue(&ctx.host, now) {
                    ctx.correlation = self
                        .correlator
                        .cookie(&ctx.host, &token, now)
                        .map(|key| format!("session:{key}"));
                    ctx.correlation_cookie = Some(format!(
                        "{}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1800",
                        openwaf_security::correlation::COOKIE
                    ));
                }
            }
        }
        if self.config.is_none()
            && let Some(client) = ctx.client
        {
            self.observe_country(ctx, client.ip());
        }
        ctx.checked(
            "routing",
            if ctx.route.is_some() {
                "matched"
            } else {
                "standalone"
            },
        );
        use openwaf_security::traffic::Verdict;
        match self.flood_protection(ctx) {
            Verdict::Allow => {}
            Verdict::Limited(retry) => {
                if let Some(request) = &mut ctx.telemetry {
                    request.blocked();
                }
                return self.reply(session, ctx, 429, Some(retry)).await;
            }
            Verdict::Unavailable | Verdict::Deny => {
                ctx.security_layer = match ctx.security_layer {
                    "ddos_global" => "ddos_global_capacity",
                    _ => "ddos_route_capacity",
                };
                return self.reject(session, ctx, 503).await;
            }
        }
        ctx.decision_trace.begin("admission");
        ctx.security_layer = "admission";
        let (class, route_id, quota) = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .map(|(s, r)| {
                let route = &s.document.routes[r];
                (
                    route
                        .admission_class
                        .unwrap_or(openwaf_config::traffic::Class::Api),
                    route.id.as_str(),
                    route.admission.clone(),
                )
            })
            .unwrap_or((
                openwaf_config::traffic::Class::Api,
                "standalone",
                Default::default(),
            ));
        let Some(client) = ctx.client else {
            return self.reject(session, ctx, 400).await;
        };
        ctx._permit = match self
            .admission
            .admit(class, route_id, &quota, client.ip())
            .await
        {
            Ok(lease) => Some(lease),
            Err(reason) => {
                ctx.security_layer = reason.label();
                return self
                    .reply(
                        session,
                        ctx,
                        reason.status(),
                        (reason.status() == 429).then_some(1),
                    )
                    .await;
            }
        };
        ctx.checked("admission", "passed");
        let timeouts = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(snapshot, route)| snapshot.timeouts(route))
            .cloned()
            .unwrap_or_default();
        ctx.retry.policy = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .map(|(s, r)| s.document.routes[r].retry.clone())
            .unwrap_or_default();
        let total = ctx
            .retry
            .policy
            .total_timeout_ms
            .unwrap_or(timeouts.total_ms)
            .min(timeouts.total_ms);
        let body_idle = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes[r].body.as_ref())
            .map_or(30000, |b| b.idle_timeout_ms);
        ctx.effective_timeouts = Some(
            serde_json::json!({"total_ms":total,"connect_ms":timeouts.connect_ms,"tls_ms":timeouts.tls_ms.unwrap_or(timeouts.connect_ms),"header_ms":timeouts.header_ms.unwrap_or(timeouts.read_ms),"request_body_idle_ms":body_idle,"response_idle_ms":timeouts.response_idle_ms.unwrap_or(timeouts.read_ms),"write_ms":timeouts.write_ms,"pool_idle_ms":timeouts.idle_ms,"drain_ms":5000}),
        );
        ctx.retry.expires = std::time::Instant::now() + Duration::from_millis(total);
        lifetime::admitted(Duration::from_millis(total))?;
        ctx.retry.valid_key = retry::key(session.req_header());
        if ctx.retry.policy.mode == openwaf_config::retry::Mode::Idempotent && !ctx.retry.valid_key
        {
            ctx.retry.disabled_reason = Some("invalid_idempotency_key");
        }
        session
            .as_mut()
            .set_write_timeout(Some(Duration::from_millis(timeouts.write_ms)));
        match self.access(ctx) {
            Verdict::Allow => {}
            Verdict::Deny => {
                if let Some(request) = &mut ctx.telemetry {
                    request.blocked();
                }
                return self.reject(session, ctx, 403).await;
            }
            Verdict::Unavailable => {
                ctx.security_layer = match ctx.security_layer {
                    "rate_limit" => "rate_limit_capacity",
                    "global_rate_limit" => "global_rate_limit_capacity",
                    layer => layer,
                };
                return self.reject(session, ctx, 503).await;
            }
            Verdict::Limited(retry) => {
                if let Some(request) = &mut ctx.telemetry {
                    request.blocked();
                }
                return self.reply(session, ctx, 429, Some(retry)).await;
            }
        }
        ctx.checked("access_policy", "passed");
        ctx.decision_trace.begin("crowdsec");
        if let Some(store) = &self.crowdsec
            && ctx
                .client
                .as_ref()
                .is_some_and(|addr| store.blocked(addr.ip()))
        {
            if let Some(request) = &mut ctx.telemetry {
                request.blocked();
            }
            ctx.security_layer = "crowdsec";
            return self.reject(session, ctx, 403).await;
        }
        if self.crowdsec.is_some() {
            ctx.signal("crowdsec", "not_banned", "observed");
        }
        ctx.checked(
            "crowdsec",
            if self.crowdsec.is_some() {
                "passed"
            } else {
                "disabled"
            },
        );
        if self.route_maintenance(session, ctx).await? {
            return Ok(true);
        }
        if self.browser_challenge(session, ctx).await? {
            return Ok(true);
        }
        let mut challenge_headers = session.req_header().headers.clone();
        openwaf_gateway::challenge::strip_cookies(&mut challenge_headers);
        session.req_header_mut().remove_header("cookie");
        session
            .req_header_mut()
            .remove_header(openwaf_gateway::challenge::HEADER);
        for value in challenge_headers.get_all("cookie") {
            session.req_header_mut().append_header("cookie", value)?;
        }
        if ctx.password_endpoint {
            return self.password_login(session, ctx).await;
        }
        ctx.decision_trace.begin("content_and_body_limits");
        if let Some(cors) = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes[r].middleware.cors.as_ref())
        {
            match cors.check(
                &session.req_header().headers,
                session.req_header().method.as_str(),
            ) {
                Ok(state) => ctx.cors = state,
                Err(status) => {
                    ctx.security_layer = "cors";
                    return self.reject(session, ctx, status).await;
                }
            }
        }
        let policy = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes[r].waf.as_ref());
        let body_settings = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes[r].body.clone());
        ctx.security_layer = "content_contract";
        let content = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes[r].content.as_ref());
        let has_body = !session.as_mut().is_body_empty();
        if has_body && ctx.cors.as_ref().is_some_and(|c| c.preflight) {
            ctx.security_layer = "cors";
            return self.reject(session, ctx, 400).await;
        }
        let parsed = if let Some(content) = content {
            match openwaf_config::traffic::headers(content, &session.req_header().headers, has_body)
            {
                Ok(parsed) => Some(parsed),
                Err(status) => return self.reject(session, ctx, status).await,
            }
        } else {
            None
        };
        // Preserve legacy MIME semantics for routes without an opt-in contract.
        let types: Vec<_> = session
            .req_header()
            .headers
            .get_all("content-type")
            .iter()
            .collect();
        if types.len() > 1 {
            return self.reject(session, ctx, 400).await;
        }
        let multipart = if let Some(parsed) = parsed {
            parsed.multipart
        } else if let Some(value) = types.first() {
            let Some(value) = value
                .to_str()
                .ok()
                .and_then(|v| v.parse::<mime::Mime>().ok())
            else {
                return self.reject(session, ctx, 400).await;
            };
            value.type_() == mime::MULTIPART
        } else {
            false
        };
        ctx.streaming = multipart
            || body_settings.as_ref().is_some_and(|b| {
                b.inspection == openwaf_config::retry::Inspection::HeadersQueryOnly
            });
        let inspected_scope = if multipart {
            "skipped_multipart"
        } else if ctx.streaming {
            "headers_query_only"
        } else {
            "full"
        };
        let cap = body_settings.as_ref().map_or(
            policy.map_or(MAX_BODY_BYTES as u64, |p| p.body_limit_bytes as u64),
            |b| b.max_body_bytes,
        );
        let body_limit = if ctx.streaming {
            cap
        } else {
            cap.min(policy.map_or(MAX_BODY_BYTES as u64, |p| p.body_limit_bytes as u64))
        };
        ctx.body_limit = body_limit;
        ctx.security_layer = "body_limit";
        let mode = policy.map_or(self.mode, waf_policy::mode);
        let inspection_timeout =
            Duration::from_millis(policy.map_or(2000, |p| p.inspection_timeout_ms));
        let pool = if mode == Mode::Off {
            None
        } else if let Some((snapshot, route)) = ctx.snapshot.as_ref().zip(ctx.route) {
            match snapshot
                .prepared
                .as_ref()
                .and_then(|prepared| prepared.downcast_ref::<waf_policy::Prepared>())
                .and_then(|p| p.routes.get(route))
                .and_then(|pool| pool.clone())
            {
                Some(pool) => Some(pool),
                None => return self.reject(session, ctx, 503).await,
            }
        } else {
            Some(self.pool.clone())
        };
        let header = session.req_header();
        let bytes: usize = header
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();
        if header.headers.len() > MAX_HEADERS
            || bytes > MAX_HEADER_BYTES
            || header.uri.to_string().len() > MAX_HEADER_BYTES
        {
            return self.reject(session, ctx, 431).await;
        }
        if header
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|len| len as u64 > body_limit)
        {
            return self.reject(session, ctx, 413).await;
        }
        // Trailers are not part of the supported application/signature contract.
        if header.headers.contains_key("trailer") || header.headers.contains_key("te") {
            ctx.security_layer = "unsupported_trailers";
            return self.reject(session, ctx, 400).await;
        }
        let upgrade = header.headers.contains_key("upgrade");
        if upgrade && !valid_websocket(header) {
            return self.reject(session, ctx, 400).await;
        }
        let expect_continue = match header.headers.get("expect") {
            None => false,
            Some(value)
                if value.as_bytes().eq_ignore_ascii_case(b"100-continue")
                    && header.headers.get_all("expect").iter().count() == 1 =>
            {
                true
            }
            Some(_) => return self.reject(session, ctx, 417).await,
        };
        // Pingora 0.9 cannot emit informational H2 responses. Reject explicitly
        // rather than letting a client wait for a 100 that will never be sent.
        if expect_continue && header.version == pingora::http::Version::HTTP_2 {
            return self.reject(session, ctx, 417).await;
        }
        if expect_continue {
            tokio::time::timeout(
                Duration::from_secs(5),
                session.as_mut().write_continue_response(),
            )
            .await
            .map_err(|_| pingora::Error::new(pingora::ErrorType::WriteTimedout))??;
        }
        ctx.security_layer = "body_limit";
        ctx.retry.empty = session.as_mut().is_body_empty() || upgrade;
        ctx.retry.capture = replay::Capture::new(&ctx.retry.policy.replay, &self.replay_budget);
        let body = if ctx.streaming {
            if has_body
                && let Some(lease) = &mut ctx._permit
                && let Err(reason) = lease.upload()
            {
                self.admission.reject(reason);
                ctx.security_layer = reason.label();
                return self.reject(session, ctx, reason.status()).await;
            }
            session
                .as_mut()
                .set_read_timeout(Some(Duration::from_millis(
                    body_settings.as_ref().map_or(30000, |b| b.idle_timeout_ms),
                )));
            Vec::new()
        } else {
            session
                .as_mut()
                .set_read_timeout(Some(Duration::from_millis(body_idle)));
            let read = async {
                let mut body = Vec::new();
                if !upgrade {
                    while let Some(chunk) = session.read_request_body().await? {
                        if let Some(recording) = &mut ctx.body_recording {
                            recording.request.push(&chunk, false);
                        }
                        ctx.metadata
                            .received(session.as_ref().body_bytes_read() as u64, false);
                        if chunk.len() as u64 > body_limit.saturating_sub(body.len() as u64) {
                            return Ok(None);
                        }
                        body.extend_from_slice(&chunk);
                    }
                }
                if !upgrade && let Some(recording) = &mut ctx.body_recording {
                    recording.request.push(&[], true);
                }
                ctx.metadata
                    .received(session.as_ref().body_bytes_read() as u64, !upgrade);
                Ok::<_, Box<pingora::Error>>(Some(body))
            };
            let body = match read.await {
                Ok(Some(body)) => body,
                Ok(None) => return self.reject(session, ctx, 413).await,
                Err(error) => {
                    let timeout = matches!(error.etype(), pingora::ErrorType::ReadTimedout);
                    ctx.failure = Some(if timeout {
                        "request_body_idle"
                    } else {
                        "client_body_error"
                    });
                    return self
                        .reject(session, ctx, if timeout { 408 } else { 400 })
                        .await;
                }
            };
            ctx.retry.body_seen = body.len() as u64;
            let bytes = bytes::Bytes::copy_from_slice(&body);
            ctx.retry.capture.push(&bytes, true);
            if !bytes.is_empty() {
                ctx.retry.prebuffered = Some(bytes);
            }
            body
        };
        if let Some(parsed) = parsed {
            ctx.security_layer = "content_contract";
            if let Err(status) = openwaf_config::traffic::body(parsed, &body) {
                return self.reject(session, ctx, status).await;
            }
        }
        if let Some(schema) = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes[r].middleware.api_schema.as_ref())
        {
            let outcome = schema.check(
                session
                    .req_header()
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok()),
                &body,
            );
            let blocking = schema.mode == openwaf_config::api_schema::Mode::Block;
            let invalid = outcome != openwaf_config::api_schema::Outcome::Valid;
            if outcome == openwaf_config::api_schema::Outcome::OverBudget {
                ctx.signal("api_schema", "validation_capacity", "capacity_error");
                ctx.security_layer = "api_schema_capacity";
                return self.reject(session, ctx, 503).await;
            }
            ctx.signal(
                "api_schema",
                if invalid {
                    "structural_mismatch"
                } else {
                    "structural_valid"
                },
                if invalid && blocking {
                    "enforced_block"
                } else if invalid {
                    "would_block"
                } else {
                    "observed"
                },
            );
            if invalid && blocking {
                ctx.security_layer = "api_schema";
                if let Some(r) = &mut ctx.telemetry {
                    r.blocked();
                }
                return self.reject(session, ctx, 400).await;
            }
        }
        if upgrade {
            session
                .as_mut()
                .set_read_timeout(Some(Duration::from_millis(
                    timeouts.response_idle_ms.unwrap_or(timeouts.read_ms),
                )));
        }
        ctx.checked("content_and_body_limits", "passed");
        ctx.decision_trace.begin("waf");
        ctx.security_layer = "waf_capacity";
        let ticket = if let Some(pool) = &pool {
            match pool.try_reserve_priority(class == openwaf_config::traffic::Class::Critical) {
                Ok(ticket) => Some(ticket),
                Err(_) => return self.reject(session, ctx, 503).await,
            }
        } else {
            None
        };
        let header = session.req_header();
        let request = Request {
            inspect_body: !ctx.streaming,
            uri: String::from_utf8_lossy(header.raw_path()).into_owned(),
            method: header.method.to_string(),
            version: match header.version {
                pingora::http::Version::HTTP_2 => "2.0",
                _ => "1.1",
            }
            .into(),
            client: ctx.client.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
            server: self.listener,
            headers: header
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            body,
        };
        let (Some(pool), Some(ticket)) = (pool, ticket) else {
            if let Some((snapshot, route)) = ctx.snapshot.as_ref().zip(ctx.route) {
                self.shadow.offer(
                    &snapshot.document.routes[route].id,
                    &ctx.request_id,
                    &request,
                    false,
                    snapshot.version,
                    inspected_scope,
                );
            }
            ctx.security_layer = "allow";
            ctx.body_inspection = "off";
            ctx.checked("waf", "disabled");
            return self.after_inspection(session, ctx).await;
        };
        ctx.security_layer = "waf";
        let shadow_request = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .filter(|(s, r)| {
                self.shadow
                    .interested(&s.document.routes[*r].id, &ctx.request_id, s.version)
            })
            .map(|_| request.clone());
        if let Some((snapshot, route)) = ctx.snapshot.as_ref().zip(ctx.route) {
            snapshot.waf_usage[route].record(
                snapshot.document.routes[route].waf.as_ref(),
                openwaf_telemetry::now_ms(),
            );
        }
        match pool
            .inspect_report(ticket, request, inspection_timeout)
            .await
        {
            Ok(report) => {
                ctx.waf_observed_at_unix_ms = openwaf_telemetry::now_ms();
                ctx.body_inspection = if inspected_scope == "full" && !report.body_inspected {
                    "headers_query_only"
                } else {
                    inspected_scope
                };
                let blocked = report.decision == Decision::Block && mode == Mode::On;
                ctx.waf_enforced = blocked;
                if let (Some((snapshot, route)), Some(shadow_request)) =
                    (ctx.snapshot.as_ref().zip(ctx.route), shadow_request)
                {
                    self.shadow.offer(
                        &snapshot.document.routes[route].id,
                        &ctx.request_id,
                        &shadow_request,
                        blocked,
                        snapshot.version,
                        ctx.body_inspection,
                    );
                }
                ctx.waf_report = Some(report);
                if blocked {
                    ctx.checked("waf", "blocked");
                    if let Some(r) = &mut ctx.telemetry {
                        r.blocked();
                    }
                    self.reject(session, ctx, 403).await
                } else {
                    ctx.security_layer = "allow";
                    ctx.checked("waf", "passed");
                    self.after_inspection(session, ctx).await
                }
            }
            Err(_) => {
                ctx.security_layer = "waf_unavailable";
                self.reject(session, ctx, 503).await
            }
        }
    }
    fn retry_buffering(&self, _ctx: &RequestContext) -> bool {
        false
    }
    fn has_replay_source(&self, ctx: &RequestContext) -> bool {
        ctx.retry.replaying
    }
    async fn read_replay_source(
        &self,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Option<bytes::Bytes>> {
        match ctx.retry.reader.as_mut() {
            Some(r) => r
                .next()
                .await
                .map_err(|_| pingora::Error::new(pingora::ErrorType::HTTPStatus(502))),
            None => Ok(None),
        }
    }
    async fn before_upstream_attempt(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        self.start_attempt(session, ctx).await
    }
    fn attempt_timer(
        &self,
        ctx: &RequestContext,
    ) -> Option<(Duration, Arc<std::sync::atomic::AtomicBool>)> {
        ctx.retry.policy.per_try_timeout_ms.map(|ms| {
            (
                Duration::from_millis(ms).min(
                    ctx.retry
                        .expires
                        .saturating_duration_since(std::time::Instant::now()),
                ),
                ctx.retry.final_headers.clone(),
            )
        })
    }
    fn upstream_attempt_failed(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        e: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        self.attempt_failed(session, ctx, e)
    }
    fn error_while_proxy(
        &self,
        _peer: &HttpPeer,
        _session: &mut Session,
        mut e: Box<pingora::Error>,
        _ctx: &mut RequestContext,
        _reused: bool,
    ) -> Box<pingora::Error> {
        e.set_retry(false);
        e
    }
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        header: &mut pingora::http::ResponseHeader,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        if header.headers.contains_key("trailer") {
            ctx.failure = Some("unsupported_response_trailers");
            return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(502)));
        }
        if !header.status.is_informational() || header.status.as_u16() == 101 {
            ctx.upstream_status = header.status.as_u16();
            ctx.passive_health.response(header);
            ctx.retry
                .final_headers
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &pingora::Error,
        ctx: &mut RequestContext,
    ) -> pingora::proxy::FailToProxy {
        use pingora::{ErrorSource, ErrorType};
        ctx.failure = ctx.failure.or(Some(match (error.esource(), error.etype()) {
            (_, ErrorType::Custom("openwaf_per_try_timeout")) => "per_try_timeout",
            (ErrorSource::Upstream, ErrorType::ReadTimedout) if ctx.retry.final_received() => {
                "response_idle"
            }
            (ErrorSource::Upstream, ErrorType::ReadTimedout) => "response_header_timeout",
            (_, ErrorType::Custom("openwaf_tls_timeout")) => "tls_timeout",
            (ErrorSource::Upstream, ErrorType::ConnectTimedout) => "connect_timeout",
            (ErrorSource::Downstream, ErrorType::ReadTimedout) => "request_body_idle",
            (ErrorSource::Downstream, ErrorType::WriteTimedout) => "downstream_write_timeout",
            (ErrorSource::Downstream, _) => "client_cancel_or_error",
            _ => "transport_error",
        }));
        let status = match error.etype() {
            ErrorType::HTTPStatus(status) => *status,
            ErrorType::Custom("openwaf_per_try_timeout" | "openwaf_tls_timeout") => 504,
            _ => match error.esource() {
                ErrorSource::Upstream => {
                    if matches!(
                        error.etype(),
                        ErrorType::ConnectTimedout
                            | ErrorType::ReadTimedout
                            | ErrorType::WriteTimedout
                            | ErrorType::Custom("openwaf_per_try_timeout")
                    ) {
                        504
                    } else {
                        502
                    }
                }
                ErrorSource::Downstream => match error.etype() {
                    ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                    ErrorType::ReadTimedout => 408,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        // A failed stream cannot be replaced with a second final response.
        let sent = if status > 0 && !retry::final_response_written(session) {
            match self.reject(session, ctx, status).await {
                Ok(_) => true,
                Err(_) => {
                    // Bounded diagnostics, without synchronous hot-path logging
                    // or exposing request/response values in an error message.
                    self.response_write_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    false
                }
            }
        } else {
            false
        };
        pingora::proxy::FailToProxy {
            error_code: if sent { status } else { 0 },
            can_reuse_downstream: false,
        }
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        header: &mut pingora::http::ResponseHeader,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        if !header.status.is_informational() || header.status.as_u16() == 101 {
            self.response_headers(header, ctx)?;

            if let Some(cookie) = &ctx.affinity_cookie {
                header.append_header("set-cookie", cookie)?;
            }

            ctx.metadata.response_headers(&header.headers);
            let empty = _session.req_header().method == "HEAD"
                || matches!(header.status.as_u16(), 101 | 204 | 304)
                || header
                    .headers
                    .get("content-length")
                    .is_some_and(|v| v == "0");
            ctx.record_response_header(header, empty);
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Box<HttpPeer>> {
        let mut peer = if let Some(snapshot) = &ctx.snapshot {
            let upstream = ctx
                .route
                .and_then(|r| snapshot.upstream_for_route(r))
                .map(|u| &snapshot.document.upstreams[u])
                .ok_or_else(|| pingora::Error::new(pingora::ErrorType::HTTPStatus(503)))?;
            let mut preferred = None;
            if let Some(settings) = &upstream.affinity {
                // Host-only secure cookies require HTTPS at the gateway. Do not
                // trust spoofable forwarded-proto to enable them on plain HTTP.
                if !self.tls {
                    return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(503)));
                }
                let name = affinity::SignerKey::name(&upstream.id)
                    .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
                let values: Vec<_> = session
                    .req_header()
                    .headers
                    .get_all("cookie")
                    .iter()
                    .filter_map(|h| h.to_str().ok())
                    .flat_map(|h| h.split(';'))
                    .filter_map(|v| v.trim().split_once('='))
                    .filter(|(n, _)| *n == name)
                    .take(2)
                    .collect();
                if let [(_, value)] = values.as_slice()
                    && let Some(target) = self.affinity_key.verify(
                        &ctx.host,
                        &upstream.id,
                        value,
                        settings.lifetime_seconds,
                        openwaf_telemetry::now_ms(),
                    )
                {
                    let u = ctx
                        .route
                        .and_then(|r| snapshot.upstream_for_route(r))
                        .ok_or_else(|| pingora::Error::new(pingora::ErrorType::InternalError))?;
                    preferred = upstream
                        .endpoints
                        .iter()
                        .enumerate()
                        .find(|(i, e)| {
                            affinity::SignerKey::endpoint(&upstream.id, e).ok().as_ref()
                                == Some(&target)
                                && self.config.as_ref().is_some_and(|s| {
                                    s.1.eligible(&openwaf_config::operations::Operations::key(
                                        &upstream.id,
                                        e,
                                    ))
                                })
                                && snapshot.health.select(u, *i, 0).is_some()
                        })
                        .map(|(i, _)| i);
                    if preferred.is_none()
                        && settings.fallback == openwaf_config::affinity::Fallback::Reject
                    {
                        return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(503)));
                    }
                }
            }
            let (endpoint, timeouts, selected) = ctx
                .route
                .and_then(|route| {
                    snapshot.endpoint_with_load(
                        route,
                        |i, e| {
                            let pin = ctx.retry.policy.mode
                                == openwaf_config::retry::Mode::Idempotent
                                && ctx.retry.policy.idempotency_scope
                                    == openwaf_config::retry::Scope::Endpoint
                                && ctx.retry.sent_any;
                            let operational = self.config.as_ref().is_none_or(|m| {
                                snapshot.upstream_for_route(route).is_some_and(|u| {
                                    m.1.eligible(&openwaf_config::operations::Operations::key(
                                        &snapshot.document.upstreams[u].id,
                                        e,
                                    ))
                                })
                            });
                            operational
                                && preferred.is_none_or(|target| target == i)
                                && (!pin || ctx.retry.affinity == Some(i))
                        },
                        |_, e| {
                            let u = upstream;
                            self.config.as_ref().map_or((0, 1000), |m| {
                                m.1.load(
                                    &openwaf_config::operations::Operations::key(&u.id, e),
                                    u.balancing.slow_start_ms,
                                )
                            })
                        },
                    )
                })
                .ok_or_else(|| pingora::Error::new(pingora::ErrorType::HTTPStatus(503)))?;
            let mut peer = HttpPeer::new(
                selected.address,
                endpoint.protocol == openwaf_config::Protocol::Https,
                endpoint.tls_server_name.clone().unwrap_or_default(),
            );
            let index = ctx
                .route
                .and_then(|r| snapshot.upstream_for_route(r))
                .and_then(|u| {
                    snapshot.document.upstreams[u]
                        .endpoints
                        .iter()
                        .position(|e| {
                            e.address == endpoint.address
                                && e.protocol == endpoint.protocol
                                && e.tls_server_name == endpoint.tls_server_name
                                && e.tls_verify == endpoint.tls_verify
                        })
                });
            ctx.endpoint_lease = None;
            if let Some(store) = &self.config {
                let u = ctx
                    .route
                    .and_then(|r| snapshot.upstream_for_route(r))
                    .ok_or_else(|| pingora::Error::new(pingora::ErrorType::InternalError))?;
                let key = openwaf_config::operations::Operations::key(
                    &snapshot.document.upstreams[u].id,
                    endpoint,
                );
                let lease = store
                    .1
                    .acquire(&key)
                    .ok_or_else(|| pingora::Error::new(pingora::ErrorType::HTTPStatus(503)))?;
                lifetime::endpoint(lease.cancellation());
                ctx.endpoint_lease = Some(lease);
            }
            if let Some(settings) = &upstream.affinity {
                ctx.affinity_cookie = Some(
                    self.affinity_key
                        .issue(
                            &ctx.host,
                            &upstream.id,
                            endpoint,
                            settings.lifetime_seconds,
                            openwaf_telemetry::now_ms(),
                        )
                        .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?,
                );
            }
            ctx.retry.last_endpoint = index;
            if ctx.retry.affinity.is_none() {
                ctx.retry.affinity = index;
            }
            if let Some(a) = ctx.retry.attempts.last_mut() {
                a.endpoint = Some(endpoint.address.clone().into());
            }
            peer.options.verify_cert = endpoint.tls_verify;
            peer.options.verify_hostname = endpoint.tls_verify;
            ctx.peer = Some(selected);
            peer.options.connection_timeout = Some(Duration::from_millis(timeouts.connect_ms));
            peer.options.tls_timeout = Some(Duration::from_millis(
                timeouts.tls_ms.unwrap_or(timeouts.connect_ms),
            ));
            peer.options.total_connection_timeout = Some(Duration::from_millis(
                timeouts.connect_ms + timeouts.tls_ms.unwrap_or(timeouts.connect_ms),
            ));
            peer.options.response_header_timeout = Some(Duration::from_millis(
                timeouts.header_ms.unwrap_or(timeouts.read_ms),
            ));
            peer.options.response_idle_timeout = Some(Duration::from_millis(
                timeouts.response_idle_ms.unwrap_or(timeouts.read_ms),
            ));
            peer.options.read_timeout = Some(Duration::from_millis(timeouts.read_ms));
            peer.options.write_timeout = Some(Duration::from_millis(timeouts.write_ms));
            // Eligibility is checked before looking up the address-keyed connection pool.
            peer.options.idle_timeout = Some(Duration::from_millis(timeouts.idle_ms));
            peer
        } else {
            let mut peer = HttpPeer::new(self.upstream, false, String::new());
            peer.options.connection_timeout = Some(Duration::from_secs(3));
            peer.options.read_timeout = Some(Duration::from_secs(10));
            peer.options.write_timeout = Some(Duration::from_secs(10));
            peer
        };
        peer.options.reject_http_trailers = true;
        peer.options.ca = self.upstream_ca.clone();
        Ok(Box::new(peer))
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end: bool,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        ctx.metadata.received(
            session.as_ref().body_bytes_read() as u64,
            end && !ctx.retry.replaying,
        );
        if !ctx.retry.replaying {
            let bytes = body.clone().unwrap_or_default();
            if bytes.len() as u64 > ctx.body_limit.saturating_sub(ctx.retry.body_seen) {
                ctx.security_layer = "body_limit";
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(413)));
            }
            if ctx.streaming
                && let Some(recording) = &mut ctx.body_recording
            {
                recording.request.push(&bytes, end);
            }
            ctx.retry.body_seen += bytes.len() as u64;
            ctx.retry.capture.push(&bytes, end);
        }
        if let Some(a) = ctx.retry.attempts.last_mut() {
            a.body_bytes += body.as_ref().map_or(0, |b| b.len() as u64);
        }
        if let Some(request) = &mut ctx.telemetry {
            request.received_total(session.as_ref().body_bytes_read() as u64);
        }
        Ok(())
    }
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end: bool,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Option<Duration>> {
        ctx.record_response_chunk(body.as_deref().unwrap_or_default(), end);
        Ok(None)
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end: bool,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Option<Duration>> {
        ctx.metadata.response.upstream_body_received_bytes = ctx
            .metadata
            .response
            .upstream_body_received_bytes
            .saturating_add(body.as_ref().map_or(0, |body| body.len()) as u64);
        ctx.metadata.response.upstream_body_complete |= end;
        if let Some(request) = &ctx.telemetry {
            request.response_bytes(body.as_ref().map_or(0, |body| body.len()) as u64);
        }
        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut RequestContext,
    ) {
        ctx.decision_trace.stop("interrupted");
        if let Some(a) = ctx.retry.attempts.last_mut()
            && a.error.is_none()
        {
            a.duration_ms = ctx.retry.started.elapsed().as_millis() as u64;
        }
        // Pingora also considers a failed body reader done. Only a clean EOF
        // may complete metadata; preserve partial uploads on cancellation/error.
        let body_done = error.is_none() && session.as_mut().is_body_done();
        ctx.metadata
            .received(session.as_ref().body_bytes_read() as u64, body_done);
        ctx.metadata.response.body_sent_bytes = Some(session.as_ref().body_bytes_sent() as u64);
        ctx.metadata.response.completed = error.is_none() && retry::final_response_written(session);
        ctx.metadata.completed_at_unix_ms = Some(openwaf_telemetry::now_ms());
        ctx.finish_body_recording(body_done, ctx.metadata.response.completed);
        if let Some(header) = session.response_written() {
            ctx.metadata.response_headers(&header.headers);
        }
        if let Some((snapshot, index)) = ctx.snapshot.as_ref().zip(ctx.route)
            && let Some(policy) = &snapshot.document.routes[index].middleware.detectors
        {
            let client = ctx.client.map(|c| c.ip().to_string()).unwrap_or_default();
            if ctx.metadata.response.completed {
                self.abuse.observe(
                    openwaf_security::abuse::Observation {
                        route: &snapshot.document.routes[index].id,
                        version: snapshot.version,
                        client: ctx.correlation.as_deref().unwrap_or(&client),
                        path: session.req_header().uri.path(),
                        status: session.response_written().map_or(0, |h| h.status.as_u16()),
                        upstream: ctx.upstream_status != 0
                            && session
                                .response_written()
                                .is_some_and(|h| h.status.as_u16() == ctx.upstream_status),
                        layer: ctx.security_layer,
                        request_id: &ctx.request_id,
                        started_ms: ctx.metadata.started_at_unix_ms,
                        completed_ms: openwaf_telemetry::now_ms(),
                    },
                    policy,
                );
            } else {
                self.abuse.observation_lost();
            }
        }
        if let Some(mut request) = ctx.telemetry.take() {
            request.security(
                ctx.body_inspection,
                ctx.waf_report
                    .as_ref()
                    .is_some_and(|r| r.decision == Decision::Block),
                ctx.waf_report.as_ref().map_or(0, |r| r.findings.len()),
                ctx.waf_report.as_ref().is_some_and(|r| r.truncated),
            );
            request.request_id = ctx.request_id.clone();
            request.details = ctx.details(
                ctx.failure.unwrap_or(if error.is_some() {
                    "transport_error"
                } else {
                    "completed"
                }),
                retry::final_response_written(session),
                session.response_written().map_or(0, |h| h.status.as_u16()),
            );
            let cancelled = error.is_some_and(|e| {
                e.esource() == &pingora::ErrorSource::Downstream
                    && matches!(
                        e.etype(),
                        pingora::ErrorType::ReadError
                            | pingora::ErrorType::WriteError
                            | pingora::ErrorType::ConnectionClosed
                    )
            });
            if cancelled {
                request.config_version = ctx.snapshot.as_ref().map_or(0, |s| s.version);
                request.route_index = ctx.route;
                // Dropping an unfinished telemetry request records cancellation,
                // preserving observed headers without inventing a completed response.
                return;
            }
            request.finish(
                session.response_written().map_or(0, |h| h.status.as_u16()),
                ctx.snapshot.as_ref().map_or(0, |s| s.version),
                ctx.route,
                error.is_some_and(|e| e.esource() == &pingora::ErrorSource::Upstream),
                session.as_ref().body_bytes_read() as u64,
                session.as_ref().body_bytes_sent() as u64,
            );
        }
        if let (Some(error), Some(peer)) = (error, &ctx.peer) {
            ctx.passive_health.failure(error, peer);
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        if let Some(request) = &mut ctx.telemetry {
            request.forwarded();
        }
        ctx.retry.sent_any = true;
        ctx.retry.affinity = ctx.retry.last_endpoint;
        if let Some(a) = ctx.retry.attempts.last_mut() {
            a.request_started = true;
        }
        header.insert_header("x-request-id", &ctx.request_id)?;
        // Rebuild identity from the captured trusted-proxy policy.
        for name in [
            "expect",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
        ] {
            header.remove_header(name);
        }
        let forwarded_names: Vec<_> = header
            .headers
            .keys()
            .filter(|name| name.as_str().starts_with("x-forwarded-"))
            .cloned()
            .collect();
        for name in forwarded_names {
            header.remove_header(&name);
        }
        if ctx.snapshot.is_some() {
            header.insert_header("x-openwaf-hop", "1")?;
            if let Some(client) = ctx.client {
                header.insert_header("x-forwarded-for", client.ip().to_string())?;
                header.insert_header("x-real-ip", client.ip().to_string())?;
            }
            header.insert_header("x-forwarded-host", &ctx.host)?;
            header.insert_header("x-forwarded-proto", if self.tls { "https" } else { "http" })?;
        }
        if let Some(route) = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .map(|(s, r)| &s.document.routes[r])
        {
            for name in &route.middleware.request_headers.remove {
                header.remove_header(name);
            }
            for field in &route.middleware.request_headers.set {
                header.insert_header(field.name.clone(), field.value.as_str())?;
            }
            if let Some(auth) = &route.middleware.forward_auth {
                for name in &auth.response_headers {
                    header.remove_header(name);
                }
            }
            for (name, value) in &ctx.auth_identity {
                header.insert_header(name.clone(), value)?;
            }
            if let Some(uri) = &ctx.rewritten_uri {
                header.set_uri(uri.clone());
            }
            if let Some(prefix) = route
                .middleware
                .rewrite
                .as_ref()
                .and_then(|r| r.strip_prefix.as_ref())
                .filter(|p| p.as_str() != "/")
            {
                header.insert_header("x-forwarded-prefix", prefix)?;
            }
        }
        Ok(())
    }
}

fn valid_websocket(header: &RequestHeader) -> bool {
    let single = |name: &str| {
        let mut values = header.headers.get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        if values.next().is_some() {
            return None;
        }
        Some(value)
    };
    header.method == "GET"
        && header.version == pingora::http::Version::HTTP_11
        && single("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && single("sec-websocket-version") == Some("13")
        && single("sec-websocket-key").is_some_and(|key| {
            key.len() == 24
                && openssl::base64::decode_block(key).is_ok_and(|bytes| bytes.len() == 16)
        })
        && header.headers.get_all("connection").iter().any(|v| {
            v.to_str().is_ok_and(|v| {
                v.split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
        && !header.headers.contains_key("transfer-encoding")
        && !header.headers.contains_key("expect")
        && (!header.headers.contains_key("content-length") || single("content-length") == Some("0"))
}

impl Gateway {
    async fn after_inspection(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        if self.password_check(session, ctx).await? {
            return Ok(true);
        }
        let mut cookies = session.req_header().headers.clone();
        openwaf_gateway::password_protect::strip_cookies(&mut cookies);
        session.req_header_mut().remove_header("cookie");
        for value in cookies.get_all("cookie") {
            session.req_header_mut().append_header("cookie", value)?;
        }
        if ctx.cors.as_ref().is_some_and(|c| c.preflight) {
            // Browser preflight has no application credentials. ACL/rate/CrowdSec/WAF
            // have run; the subsequent actual request must still pass ForwardAuth.
            let mut header = pingora::http::ResponseHeader::build(204, Some(8))?;
            self.response_headers(&mut header, ctx)?;
            ctx.record_response_header(&header, true);
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }
        let policy = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .map(|(s, r)| s.document.routes[r].middleware.clone())
            .unwrap_or_default();
        if let Some(rewrite) = &policy.rewrite {
            ctx.rewritten_uri = match rewrite.apply(&session.req_header().uri) {
                Ok(uri) => Some(uri),
                Err(_) => {
                    ctx.security_layer = "rewrite";
                    return self.reject(session, ctx, 400).await;
                }
            };
        }
        if let Some(auth) = &policy.forward_auth {
            ctx.decision_trace.begin("forward_auth");
            ctx.security_layer = "forward_auth";
            let target = ctx.snapshot.as_ref().and_then(|s| {
                s.auth_endpoint(&auth.upstream, |e| {
                    self.config.as_ref().is_none_or(|m| {
                        m.1.eligible(&openwaf_config::operations::Operations::key(
                            &auth.upstream,
                            e,
                        ))
                    })
                })
            });
            let Some((endpoint, peer)) = target else {
                ctx.failure = Some("forward_auth_unavailable");
                return self.reject(session, ctx, 503).await;
            };
            let Some(client) = ctx.client else {
                return self.reject(session, ctx, 503).await;
            };
            let auth_lease = self.config.as_ref().and_then(|m| {
                m.1.acquire(&openwaf_config::operations::Operations::key(
                    &auth.upstream,
                    endpoint,
                ))
            });
            if self.config.is_some() && auth_lease.is_none() {
                return self.reject(session, ctx, 503).await;
            }
            if let Some(lease) = &auth_lease {
                lifetime::endpoint(lease.cancellation());
            }
            let result = self
                .forward_auth
                .check(
                    endpoint,
                    peer.address,
                    auth,
                    openwaf_gateway::forward_auth::Original {
                        header: session.req_header(),
                        host: session
                            .req_header()
                            .headers
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or(&ctx.host),
                        client: client.ip(),
                        tls: self.tls,
                    },
                )
                .await;
            drop(auth_lease);
            match result {
                Ok(reply) => {
                    ctx.auth_identity = reply.identity;
                    ctx.auth_headers = reply.headers;
                    if !(200..300).contains(&reply.status) {
                        ctx.failure = Some("forward_auth_denied");
                        if let Some(request) = &mut ctx.telemetry {
                            request.blocked();
                        }
                        if (300..400).contains(&reply.status) {
                            ctx.checked("forward_auth", "denied");
                            let mut header =
                                pingora::http::ResponseHeader::build(reply.status, Some(8))?;
                            header.insert_header("content-length", "0")?;
                            header.insert_header("cache-control", "no-store")?;
                            self.response_headers(&mut header, ctx)?;
                            session.as_mut().set_keepalive(None);
                            ctx.record_response_header(&header, true);
                            session
                                .write_response_header(Box::new(header), true)
                                .await?;
                            return Ok(true);
                        }
                        return self.reject(session, ctx, reply.status).await;
                    }
                }
                Err(error) => {
                    use openwaf_gateway::forward_auth::Error;
                    ctx.failure = Some(match error {
                        Error::Capacity => "forward_auth_capacity",
                        Error::Unavailable => "forward_auth_unavailable",
                    });
                    return self.reject(session, ctx, 503).await;
                }
            }
        }
        if policy.forward_auth.is_some() {
            if policy.detectors.is_some()
                && let Some(auth) = &policy.forward_auth
                && let [name] = auth.identity_headers.as_slice()
                && let Some(value) = ctx.auth_identity.get(name)
            {
                let route = ctx
                    .snapshot
                    .as_ref()
                    .zip(ctx.route)
                    .map(|(s, r)| s.document.routes[r].id.as_str())
                    .unwrap_or("standalone");
                let namespace = format!(
                    "{}:{}{}:{}{}:{}",
                    auth.upstream.len(),
                    auth.upstream,
                    auth.path.len(),
                    auth.path,
                    name.len(),
                    name
                );
                if let Some(key) = self
                    .correlator
                    .verified(route, &namespace, value.as_bytes())
                {
                    ctx.correlation = Some(format!("verified:{key}"));
                }
            }
            ctx.signal("forward_auth", "authenticated", "observed");
            ctx.checked("forward_auth", "passed");
        }
        if let Some(quota) = &policy.identity_rate_limit {
            let auth = policy
                .forward_auth
                .as_ref()
                .ok_or_else(|| pingora::Error::new(pingora::ErrorType::InternalError))?;
            let route_id = ctx
                .snapshot
                .as_ref()
                .zip(ctx.route)
                .map(|(s, r)| s.document.routes[r].id.as_str())
                .unwrap_or("standalone");
            let identity = ctx.auth_identity.get(&quota.header).map(|v| v.as_bytes());
            let missing = identity.is_none_or(|v| v.is_empty() || v.len() > 1024);
            let verdict = self.principal_limiter.check(
                route_id,
                auth,
                quota,
                identity,
                std::time::Instant::now(),
            );
            ctx.security_layer = "identity_rate_limit";
            use openwaf_security::traffic::Verdict;
            ctx.signal(
                "identity_rate_limit",
                if missing {
                    "missing_principal"
                } else {
                    "verified_principal_quota"
                },
                match verdict {
                    Verdict::Allow => "observed",
                    Verdict::Unavailable => "capacity_error",
                    _ => "enforced_block",
                },
            );
            match verdict {
                Verdict::Allow => {}
                Verdict::Limited(retry) => {
                    if let Some(r) = &mut ctx.telemetry {
                        r.blocked();
                    }
                    return self.reply(session, ctx, 429, Some(retry)).await;
                }
                Verdict::Deny => {
                    if let Some(r) = &mut ctx.telemetry {
                        r.blocked();
                    }
                    return self.reject(session, ctx, 403).await;
                }
                Verdict::Unavailable => return self.reject(session, ctx, 503).await,
            }
        }
        ctx.security_layer = "allow";
        if self.application_response(session, ctx).await? {
            return Ok(true);
        }
        self.redirect(session, ctx).await
    }
    fn observe_country(&self, ctx: &mut RequestContext, client: std::net::IpAddr) {
        use openwaf_gateway::error_pages::Location;
        use openwaf_telemetry::dimensions::Country;
        let country = match &self.geoip {
            None => Country::Unavailable,
            Some(db) => match db.country(client) {
                Ok(Some(code)) => Country::Code(code),
                Ok(None) => Country::Unknown,
                Err(_) => Country::LookupFailed,
            },
        };
        ctx.metadata.client.country_code = match &country {
            Country::Code(code)
                if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) =>
            {
                Some((*code).to_owned())
            }
            _ => None,
        };
        ctx.metadata.client.geoip_status = match &country {
            Country::Code(_) if ctx.metadata.client.country_code.is_some() => "known",
            Country::Code(_) | Country::Unknown => "unknown",
            Country::Unavailable => "unavailable",
            Country::LookupFailed => "lookup_failed",
        };
        ctx.location = match &country {
            Country::Code(code) => Location::country(code),
            Country::Unknown => Location::Unknown,
            Country::Unavailable => Location::Unavailable,
            Country::LookupFailed => Location::LookupFailed,
        };
        if let Some(request) = &mut ctx.telemetry {
            request.country(country);
        }
    }
    fn flood_protection(&self, ctx: &mut RequestContext) -> openwaf_security::traffic::Verdict {
        use openwaf_security::traffic::Verdict;
        ctx.decision_trace.begin("ddos");
        let Some((snapshot, route)) = ctx.snapshot.as_ref().zip(ctx.route) else {
            ctx.checked("ddos", "disabled");
            return Verdict::Allow;
        };
        let snapshot = snapshot.clone();
        let now = std::time::Instant::now();
        if let Some(limit) = snapshot.document.global_rules.ddos {
            ctx.security_layer = "ddos_global";
            let verdict = self.ddos.check_global(limit, now);
            if verdict != Verdict::Allow {
                return verdict;
            }
        }
        let route = &snapshot.document.routes[route];
        if let Some(limit) = route.access.ddos {
            ctx.security_layer = "ddos_route";
            let verdict = self.ddos.check_route(
                route
                    .admission_class
                    .unwrap_or(openwaf_config::traffic::Class::Api),
                &route.id,
                limit,
                now,
            );
            if verdict != Verdict::Allow {
                return verdict;
            }
        }
        ctx.checked(
            "ddos",
            if snapshot.document.global_rules.ddos.is_some() || route.access.ddos.is_some() {
                "passed"
            } else {
                "disabled"
            },
        );
        Verdict::Allow
    }
    fn access(&self, ctx: &mut RequestContext) -> openwaf_security::traffic::Verdict {
        use openwaf_security::traffic::Verdict;
        ctx.decision_trace.begin("access_policy");
        let Some((snapshot, route)) = ctx.snapshot.as_ref().zip(ctx.route) else {
            return Verdict::Allow;
        };
        let Some(client) = ctx.client else {
            return Verdict::Unavailable;
        };
        let snapshot = snapshot.clone();
        for (policy, global) in [
            (&snapshot.document.global_rules, true),
            (&snapshot.document.routes[route].access, false),
        ] {
            ctx.decision_trace.begin(if global {
                "global_rules"
            } else {
                "access_policy"
            });
            ctx.security_layer = if global { "global_acl" } else { "acl" };
            if !policy.permits_ip(client.ip()) {
                ctx.signal(ctx.security_layer, "ip_denied", "enforced_block");
                return Verdict::Deny;
            }
            ctx.signal(ctx.security_layer, "ip_permitted", "observed");
            if let Some(geo) = &policy.geo {
                ctx.security_layer = if global { "global_geoip" } else { "geoip" };
                let Some(database) = &self.geoip else {
                    return Verdict::Unavailable;
                };
                let Ok(country) = database.country(client.ip()) else {
                    return Verdict::Unavailable;
                };
                if !geo.permits(country) {
                    ctx.signal(ctx.security_layer, "country_denied", "enforced_block");
                    return Verdict::Deny;
                }
                ctx.signal(ctx.security_layer, "country_permitted", "observed");
            }
            if let Some(limit) = policy.rate_limit {
                ctx.security_layer = if global {
                    "global_rate_limit"
                } else {
                    "rate_limit"
                };
                let verdict = if global {
                    // Dedicated bounded limiter: one per-client budget across every route/class.
                    self.global_rate_limiter.check(
                        openwaf_config::traffic::Class::Api,
                        "global",
                        client.ip(),
                        limit,
                        std::time::Instant::now(),
                    )
                } else {
                    self.rate_limiter.check(
                        snapshot.document.routes[route]
                            .admission_class
                            .unwrap_or(openwaf_config::traffic::Class::Api),
                        &snapshot.document.routes[route].id,
                        client.ip(),
                        limit,
                        std::time::Instant::now(),
                    )
                };
                ctx.signal(
                    ctx.security_layer,
                    "ip_quota",
                    match verdict {
                        Verdict::Allow => "observed",
                        Verdict::Unavailable => "capacity_error",
                        _ => "enforced_block",
                    },
                );
                if verdict != Verdict::Allow {
                    return verdict;
                }
            }
            if global {
                ctx.checked("global_rules", "passed");
            }
        }
        Verdict::Allow
    }
    fn response_headers(
        &self,
        header: &mut pingora::http::ResponseHeader,
        ctx: &RequestContext,
    ) -> pingora::Result<()> {
        header.insert_header("x-request-id", &ctx.request_id)?;
        if let Some(route) = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes.get(r))
        {
            for name in &route.middleware.response_headers.remove {
                header.remove_header(name);
            }
            for field in &route.middleware.response_headers.set {
                header.insert_header(field.name.clone(), field.value.as_str())?;
            }
            for (name, value) in route.security_headers.values(self.tls) {
                header.insert_header(name, value)?;
            }
            if let Some(cors) = &route.middleware.cors {
                let mut fields = header.headers.clone();
                cors.apply(ctx.cors.as_ref(), &mut fields)
                    .map_err(|_| pingora::Error::new(pingora::ErrorType::HTTPStatus(503)))?;
                for name in [
                    "vary",
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-expose-headers",
                    "access-control-allow-methods",
                    "access-control-allow-headers",
                    "access-control-max-age",
                ] {
                    header.remove_header(name);
                    for value in fields.get_all(name) {
                        header.append_header(name, value)?;
                    }
                }
            }
            // Authenticated application responses must not be shared by a CDN/cache.
            if route.middleware.forward_auth.is_some()
                || route.middleware.detectors.is_some()
                || route.password_protect.is_some()
                || route.access.challenge.is_some()
                || ctx
                    .snapshot
                    .as_ref()
                    .is_some_and(|s| s.document.global_rules.challenge.is_some())
            {
                header.insert_header("cache-control", "private, no-store")?;
            }
        }
        if ctx.security_layer == "challenge" {
            header.insert_header("x-openwaf-challenge", ctx.failure.unwrap_or("required"))?;
            header.insert_header("cache-control", "private, no-store")?;
        }
        for (name, value) in &ctx.auth_headers {
            header.append_header(name.clone(), value)?;
        }
        if let Some(cookie) = &ctx.correlation_cookie {
            header.append_header("set-cookie", cookie)?;
        }
        Ok(())
    }
    async fn reject(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        status: u16,
    ) -> pingora::Result<bool> {
        self.reply(session, ctx, status, None).await
    }
    async fn reply(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        status: u16,
        retry_after: Option<u64>,
    ) -> pingora::Result<bool> {
        if matches!(
            ctx.security_layer,
            "crowdsec"
                | "geoip"
                | "global_geoip"
                | "rate_limit_capacity"
                | "global_rate_limit_capacity"
                | "challenge"
                | "forward_auth"
        ) {
            ctx.signal(
                ctx.security_layer,
                ctx.failure.unwrap_or("gate_outcome"),
                if status == 503 {
                    "capacity_error"
                } else {
                    "enforced_block"
                },
            );
        }
        ctx.decision_trace.stop("stopped");
        session.as_mut().set_keepalive(None);
        let mut header = pingora::http::ResponseHeader::build(status, Some(8))?;
        let message = openwaf_gateway::error_pages::message(status);
        let json = session
            .req_header()
            .headers
            .get("accept")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.contains("application/json"));
        let body = if json {
            serde_json::json!({"status":status,"message":message,"request_id":ctx.request_id})
                .to_string()
        } else {
            ctx.snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.error_page(ctx.route, status))
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    openwaf_gateway::error_pages::default_html(
                        status,
                        &ctx.request_id,
                        ctx.client.map(|client| client.ip()),
                        &ctx.location,
                    )
                })
        };
        self.response_headers(&mut header, ctx)?;
        header.insert_header(
            "content-type",
            if json {
                "application/json"
            } else {
                "text/html; charset=utf-8"
            },
        )?;
        header.insert_header("cache-control", "no-store")?;
        header.insert_header("content-security-policy", openwaf_gateway::error_pages::CSP)?;
        header.insert_header("x-content-type-options", "nosniff")?;
        header.insert_header("x-frame-options", "DENY")?;
        header.insert_header("referrer-policy", "no-referrer")?;
        header.insert_header("x-request-id", &ctx.request_id)?;
        if let Some(retry) = retry_after {
            header.insert_header("retry-after", retry.to_string())?;
        }
        header.insert_header("content-length", body.len().to_string())?;
        let no_body = session.req_header().method == "HEAD";
        ctx.record_response_header(&header, no_body);
        session
            .write_response_header(Box::new(header), no_body)
            .await?;
        if !no_body {
            ctx.record_response_chunk(body.as_bytes(), true);
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
        }
        Ok(true)
    }
    async fn redirect(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        let redirect = ctx
            .snapshot
            .as_ref()
            .zip(ctx.route)
            .and_then(|(s, r)| s.document.routes.get(r))
            .and_then(|r| r.redirect.as_ref())
            .filter(|r| !r.http_only || !self.tls);
        let Some(redirect) = redirect else {
            return Ok(false);
        };
        // WAF has consumed and inspected the body before this response. Never
        // forward any part of a redirect request to an upstream.
        let mut header = pingora::http::ResponseHeader::build(redirect.status, Some(8))?;
        let location = redirect
            .location(&session.req_header().uri)
            .map_err(|_| pingora::Error::new(pingora::ErrorType::HTTPStatus(400)))?;
        header.insert_header("location", &location)?;
        header.insert_header("content-length", "0")?;
        self.response_headers(&mut header, ctx)?;
        ctx.record_response_header(&header, true);
        session
            .write_response_header(Box::new(header), true)
            .await?;
        Ok(true)
    }
}

fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.into())
}

fn main() -> Result<()> {
    openwaf_env::load()?;
    if env::args().nth(1).as_deref() == Some("check-resources") {
        return check_resources();
    }
    if env::args().nth(1).as_deref() == Some("probe") {
        return run_probe();
    }
    match env::var("OPENWAF_REQUIRE_MANAGED").as_deref() {
        Ok("true") => anyhow::ensure!(
            env::var("OPENWAF_DATABASE_URL").is_ok_and(|url| !url.trim().is_empty()),
            "managed deployment requires OPENWAF_DATABASE_URL"
        ),
        Ok("false") | Err(env::VarError::NotPresent) => {}
        _ => bail!("OPENWAF_REQUIRE_MANAGED must be true or false"),
    }
    let listener: SocketAddr = setting("OPENWAF_LISTEN", "127.0.0.1:8080")
        .parse()
        .context("invalid OPENWAF_LISTEN")?;
    let upstream: SocketAddr = setting("OPENWAF_UPSTREAM", "127.0.0.1:8081")
        .parse()
        .context("spike requires a numeric OPENWAF_UPSTREAM socket address")?;
    if upstream.ip().is_unspecified() || upstream.port() == 0 || listener.port() == 0 {
        bail!("listener/upstream requires a nonzero port; upstream cannot be a wildcard address");
    }
    if listener.port() == upstream.port()
        && (listener.ip() == upstream.ip() || listener.ip().is_unspecified())
    {
        bail!("upstream points to the gateway listener");
    }
    let mode = match setting("OPENWAF_WAF_MODE", "DetectionOnly").as_str() {
        "Off" => Mode::Off,
        "DetectionOnly" => Mode::DetectionOnly,
        "On" => Mode::On,
        _ => bail!("OPENWAF_WAF_MODE must be Off, DetectionOnly, or On"),
    };
    let tls_manifest = env::var_os("OPENWAF_TLS_MANIFEST").map(PathBuf::from);
    let tls_store = tls_manifest
        .as_ref()
        .map(|path| {
            openwaf_tls::Store::load(path)
                .map(Arc::new)
                .context("load initial TLS snapshot")
        })
        .transpose()?;
    let crowdsec = env::var_os("OPENWAF_CROWDSEC_CONFIG")
        .map(|path| openwaf_security::Worker::start(std::path::Path::new(&path)))
        .transpose()?;
    let budgets: openwaf_config::resources::Budgets =
        match env::var_os("OPENWAF_RESOURCE_BUDGETS_FILE") {
            Some(path) => serde_json::from_slice(&openwaf_admin::crypto::private_file(
                std::path::Path::new(&path),
                8192,
            )?)
            .context("parse node resource budgets")?,
            None => Default::default(),
        };
    budgets
        .validate()
        .context("validate node RAM/FD/queue envelope")?;
    let (fd_limit, _) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)
        .context("read process FD limit")?;
    anyhow::ensure!(
        budgets.estimated_fds() as u64 <= fd_limit,
        "resource FD envelope exceeds process soft limit"
    );
    let admission = openwaf_gateway::admission::Node::new(budgets.clone());
    let pool = Arc::new(Pool::new(
        &setting("OPENWAF_RULES", "/etc/openwaf/modsecurity.conf"),
        mode,
        budgets.waf_workers,
        budgets.waf_queue_per_worker,
    )?);
    let upstream_ca = load_upstream_ca()?;
    let health_requests = Arc::new(openwaf_config::requests::Requests::new(budgets.health_jobs));
    let compiler = waf_policy::Compiler::with_budgets(
        setting("OPENWAF_RULES", "/etc/openwaf/modsecurity.conf"),
        openwaf_waf::Configuration::new(mode),
        pool.clone(),
        budgets.waf_workers,
        budgets.waf_queue_per_worker,
    )?;
    let simulator = simulator::Service::new(
        setting("OPENWAF_RULES", "/etc/openwaf/modsecurity.conf"),
        mode,
    )?;
    let shadow = shadow::Service::new(
        setting("OPENWAF_RULES", "/etc/openwaf/modsecurity.conf"),
        budgets.waf_workers,
        budgets.waf_queue_per_worker,
    )?;
    let (telemetry, telemetry_receiver) = openwaf_telemetry::Hub::new();
    let principal_limiter = Arc::new(openwaf_security::principal::Limiter::new()?);
    let abuse = Arc::new(openwaf_security::abuse::Service::default());
    let global_rate_limiter = Arc::new(openwaf_security::traffic::Limiter::global());
    let rate_limiter = Arc::new(openwaf_security::traffic::Limiter::default());
    let ddos = Arc::new(openwaf_security::ddos::Protection::default());
    let replay_path = env::var_os("OPENWAF_REPLAY_DIRECTORY").map(PathBuf::from);
    let replay_reserve = setting("OPENWAF_REPLAY_MIN_FREE_BYTES", "67108864")
        .parse::<u64>()
        .context("invalid replay free-space reserve")?;
    let replay_budget =
        replay::Budget::configured(&budgets, replay_path.as_deref(), replay_reserve)?;
    let retry_slots = Arc::new(openwaf_gateway::admission::Gate::default());
    let body_worker = openwaf_storage::bodies::Worker::start().context("start body recorder")?;
    let body_recorder = body_worker.service.clone();
    let managed = admin::Managed::start(
        listener,
        compiler.client.clone(),
        health_requests.clone(),
        telemetry.clone(),
        telemetry_receiver,
        admin::Diagnostics {
            principal_limiter: principal_limiter.clone(),
            simulator,
            abuse: abuse.clone(),
            body_recorder: body_recorder.clone(),
            admission: admission.clone(),
            rate_limiter: rate_limiter.clone(),
            global_rate_limiter: global_rate_limiter.clone(),
            ddos: ddos.clone(),
            compiler: compiler.client.clone(),
            replay: replay_budget.clone(),
            retry_slots: retry_slots.clone(),
            shadow: shadow.clone(),
            pool: pool.clone(),
            tls: tls_store.clone(),
            crowdsec: crowdsec.as_ref().map(|(store, _)| store.clone()),
        },
    )?;
    let mut server = Server::new(None).context("create Pingora server")?;
    let config =
        Arc::get_mut(&mut server.configuration).context("Pingora configuration already shared")?;
    config.grace_period_seconds = Some(1);
    config.graceful_shutdown_timeout_seconds = Some(5);
    config.threads = 2;
    config.max_retries = 5;
    server.bootstrap();
    let geoip = env::var_os("OPENWAF_GEOIP_DB")
        .map(|path| openwaf_security::traffic::CountryDb::load(std::path::Path::new(&path)))
        .transpose()?;
    let response_write_failures = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let gateway = Gateway {
        abuse,
        body_recorder,
        principal_limiter,
        correlator: openwaf_security::correlation::Correlator::new()?,
        challenge_gate: openwaf_gateway::challenge::Gate::new()?,
        password_gate: openwaf_gateway::password_protect::Gate::new()?,
        forward_auth: openwaf_gateway::forward_auth::Client::new(
            upstream_ca.as_deref().map(|ca| ca.as_ref()),
        )?,
        affinity_key: affinity::SignerKey::load(
            env::var_os("OPENWAF_AFFINITY_KEY_FILE")
                .as_deref()
                .map(std::path::Path::new),
        )?,
        shadow,
        replay_budget,
        retry_slots,
        telemetry: telemetry.clone(),
        geoip,
        global_rate_limiter,
        rate_limiter,
        ddos,
        response_write_failures: response_write_failures.clone(),
        admission: admission.clone(),
        health_requests,
        upstream_ca,
        config: managed.as_ref().map(|managed| managed.store.clone()),
        tls: tls_store.is_some(),
        pool: pool.clone(),
        upstream,
        listener,
        mode,
        crowdsec: crowdsec.as_ref().map(|(store, _)| store.clone()),
    };
    let mut http = pingora::proxy::http_proxy(&server.configuration, gateway);
    let mut options = pingora::apps::HttpServerOptions::default();
    options.h2_idle_timeout = Some(Duration::from_secs(30));
    http.server_options = Some(options);
    let mut h2 = pingora::protocols::http::v2::server::default_h2_options();
    h2.max_concurrent_streams(32)
        .max_header_list_size(MAX_HEADER_BYTES as u32)
        .initial_window_size(MAX_BODY_BYTES as u32)
        .initial_connection_window_size(1024 * 1024)
        .max_send_buffer_size(MAX_BODY_BYTES);
    http.h2_options = Some(h2);
    let mut proxy = listener::Listener {
        endpoints: pingora::listeners::Listeners::new(),
        app: Arc::new(lifetime::Transport {
            proxy: Arc::new(http),
            telemetry,
            admission: admission.clone(),
        }),
        admission,
    };
    if let Some(store) = &tls_store {
        let mut settings = pingora::listeners::tls::TlsSettings::from(store.acceptor()?);
        settings.enable_h2();
        proxy
            .endpoints
            .add_tls_with_settings(&listener.to_string(), None, settings);
    } else {
        proxy.endpoints.add_tcp(&listener.to_string());
    }
    let reloader = tls_store
        .zip(tls_manifest)
        .map(|(store, path)| tls_reload::Reloader::start(store, path))
        .transpose()?;
    server.add_service(proxy);
    eprintln!(
        "runtime component=gateway state=started tls_reload={} body_limit_bytes={}",
        reloader.is_some(),
        MAX_BODY_BYTES
    );
    server.run(RunArgs::default());
    drop(reloader);
    drop(managed);
    drop(body_worker);
    drop(crowdsec);
    drop(compiler);
    eprintln!(
        "runtime component=proxy_response state=stopped write_failures={}",
        response_write_failures.load(std::sync::atomic::Ordering::Relaxed)
    );
    let waf = pool.stats();
    eprintln!(
        "runtime component=waf state=stopped queued={} executing={} rejected={} failed={}",
        waf.queued, waf.executing, waf.rejected, waf.failed
    );
    drop(pool);
    Ok(())
}

fn load_upstream_ca() -> Result<Option<Arc<pingora::protocols::tls::CaType>>> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let Some(path) = env::var_os("OPENWAF_UPSTREAM_CA_FILE") else {
        return Ok(None);
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open upstream CA bundle")?;
    anyhow::ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 262144,
        "upstream CA bundle must be a bounded regular file"
    );
    let mut data = Vec::new();
    file.take(262145).read_to_end(&mut data)?;
    anyhow::ensure!(data.len() <= 262144, "upstream CA bundle too large");
    let certs = openssl::x509::X509::stack_from_pem(&data).context("parse upstream CA bundle")?;
    anyhow::ensure!(
        !certs.is_empty() && certs.len() <= 128,
        "invalid upstream CA count"
    );
    Ok(Some(Arc::new(certs.into_boxed_slice())))
}

// Offline deployment validation: no native pools, database, TLS, or listener.
fn check_resources() -> Result<()> {
    use std::io::Read;
    let mut input = Vec::new();
    std::io::stdin().take(8193).read_to_end(&mut input)?;
    anyhow::ensure!(input.len() <= 8192, "resource budgets exceed 8 KiB");
    let budgets: openwaf_config::resources::Budgets =
        serde_json::from_slice(&input).context("parse node resource budgets")?;
    budgets.validate().context("validate resource envelope")?;
    let (fd_limit, _) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)?;
    anyhow::ensure!(
        budgets.estimated_fds() as u64 <= fd_limit,
        "resource FD envelope exceeds process soft limit"
    );
    println!("Resource budgets validated.");
    Ok(())
}

// Offline operator entry point sharing the authenticated API's probe service.
// No proxy/WAF or discovery collector needs to be running for this mode.
fn run_probe() -> Result<()> {
    use std::io::Read;
    let mut input = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut input)?;
    anyhow::ensure!(input.len() <= 4096, "probe request exceeds limit");
    let endpoint: openwaf_gateway::probe::Endpoint =
        serde_json::from_slice(&input).map_err(|_| {
            anyhow::anyhow!("invalid probe JSON (host, port, protocol, optional tls_server_name)")
        })?;
    let listener: SocketAddr = setting("OPENWAF_LISTEN", "127.0.0.1:8080")
        .parse()
        .context("invalid probe listener exclusion")?;
    let ca = env::var_os("OPENWAF_PROBE_CA_FILE").map(PathBuf::from);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let service = openwaf_gateway::probe::ProbeService::new(vec![listener], ca.as_deref())?;
        let report = service.test(endpoint).await;
        println!("{}", serde_json::to_string(&report)?);
        Ok(())
    })
}
