//! One logical request, bounded attempts. A complete capture is not permission.
use crate::{Gateway, RequestContext, replay};
use openwaf_config::retry::{Cause, Policy};
use pingora::proxy::Session;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Clone, Default, serde::Serialize)]
pub struct Attempt {
    pub index: u8,
    pub endpoint: Option<String>,
    pub error: Option<&'static str>,
    pub duration_ms: u64,
    pub request_started: bool,
    pub body_bytes: u64,
    pub retry: bool,
}
pub struct State {
    pub policy: Policy,
    pub attempts: Vec<Attempt>,
    pub valid_key: bool,
    pub empty: bool,
    pub sent_any: bool,
    pub final_headers: Arc<AtomicBool>,
    pub started: Instant,
    pub expires: Instant,
    pub body_seen: u64,
    pub capture: replay::Capture,
    pub reader: Option<replay::Reader>,
    pub prebuffered: Option<bytes::Bytes>,
    pub replaying: bool,
    pub affinity: Option<usize>,
    pub last_endpoint: Option<usize>,
    pub disabled_reason: Option<&'static str>,
    pub retry_permit: Option<openwaf_gateway::admission::Permit>,
}
impl Default for State {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            policy: Default::default(),
            attempts: Vec::with_capacity(5),
            valid_key: false,
            empty: true,
            sent_any: false,
            final_headers: Arc::new(AtomicBool::new(false)),
            started: now,
            expires: now + Duration::from_secs(30),
            body_seen: 0,
            capture: Default::default(),
            reader: None,
            prebuffered: None,
            replaying: false,
            affinity: None,
            last_endpoint: None,
            disabled_reason: None,
            retry_permit: None,
        }
    }
}
impl State {
    pub fn final_received(&self) -> bool {
        self.final_headers.load(Ordering::Acquire)
    }
    pub fn failed(&mut self, cause: Option<Cause>, upstream: bool) -> bool {
        let Some(cause) = cause else {
            return false;
        };
        upstream
            && self.attempts.len() < usize::from(self.policy.max_attempts)
            && !self.final_received()
            && Instant::now() < self.expires
            && self.policy.retry_on.contains(&cause)
    }
}
pub fn final_response_written(session: &Session) -> bool {
    session
        .response_written()
        .is_some_and(|header| !header.status.is_informational() || header.status.as_u16() == 101)
}
pub fn classify(e: &pingora::Error) -> Option<Cause> {
    use pingora::ErrorType::*;
    match e.etype() {
        ConnectTimedout => Some(Cause::ConnectTimeout),
        ConnectRefused | ConnectError | BindError => Some(Cause::ConnectFailure),
        ConnectionClosed | ReadError | WriteError => Some(Cause::ConnectionReset),
        WriteTimedout => Some(Cause::RequestWriteTimeout),
        ReadTimedout => Some(Cause::ResponseHeaderTimeout),
        Custom("openwaf_per_try_timeout") => Some(Cause::PerTryTimeout),
        _ => None,
    }
}
pub fn name(cause: Cause) -> &'static str {
    match cause {
        Cause::ConnectFailure => "connect_failure",
        Cause::ConnectTimeout => "connect_timeout",
        Cause::ConnectionReset => "connection_reset",
        Cause::RequestWriteTimeout => "request_write_timeout",
        Cause::ResponseHeaderTimeout => "response_header_timeout",
        Cause::PerTryTimeout => "per_try_timeout",
    }
}
pub fn key(header: &pingora::http::RequestHeader) -> bool {
    let mut values = header.headers.get_all("idempotency-key").iter();
    match (values.next(), values.next()) {
        (Some(v), None) => {
            !v.is_empty() && v.len() <= 255 && v.as_bytes().iter().all(|b| (33..=126).contains(b))
        }
        _ => false,
    }
}
impl Gateway {
    pub async fn start_attempt(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        let state = &mut ctx.retry;
        if state.attempts.len() >= usize::from(state.policy.max_attempts) {
            return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(502)));
        }
        if !state.attempts.is_empty() {
            state.retry_permit.take();
            state.retry_permit = Some(
                self.retry_slots
                    .enter(self.admission.budgets.retry_slots)
                    .ok_or_else(|| {
                        ctx.security_layer = "retry_capacity";
                        pingora::Error::new(pingora::ErrorType::HTTPStatus(503))
                    })?,
            );
            let ceiling = state
                .policy
                .backoff_base_ms
                .saturating_mul(1u64 << state.attempts.len().saturating_sub(1))
                .min(state.policy.backoff_max_ms);
            let mut random = [0; 8];
            openssl::rand::rand_bytes(&mut random)
                .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
            let delay = Duration::from_millis(u64::from_le_bytes(random) % (ceiling + 1));
            if Instant::now() + delay >= state.expires {
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(504)));
            }
            tokio::time::sleep(delay).await;
            if !state.empty && state.sent_any {
                state.reader =
                    Some(
                        state.capture.reader().await.map_err(|_| {
                            pingora::Error::new(pingora::ErrorType::HTTPStatus(502))
                        })?,
                    );
                state.replaying = true;
            }
        } else if let Some(body) = state.prebuffered.take() {
            state.reader = Some(replay::Reader::Memory(Some(body)));
            state.replaying = true;
        }
        if Instant::now() >= state.expires {
            return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(504)));
        }
        state.started = Instant::now();
        state.final_headers.store(false, Ordering::Release);
        state.attempts.push(Attempt {
            index: state.attempts.len() as u8 + 1,
            ..Default::default()
        });
        // Header-only methods can still carry bodies; emptiness comes from framing.
        let _ = session;
        Ok(())
    }
    pub fn attempt_failed(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        mut error: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        let cause = classify(&error);
        let s = &mut ctx.retry;
        let transport = error.esource() == &pingora::ErrorSource::Upstream
            || cause == Some(Cause::PerTryTimeout);
        let permitted = s.policy.authorized(
            session.req_header().method.as_str(),
            s.valid_key,
            s.sent_any,
            s.capture.complete(),
            s.empty,
        );
        let retry = permitted && s.failed(cause, transport) && !final_response_written(session);
        if let Some(a) = s.attempts.last_mut() {
            a.duration_ms = s.started.elapsed().as_millis() as u64;
            a.error = cause.map(name).or(Some("non_retryable"));
            a.retry = retry;
        }
        if !retry && s.disabled_reason.is_none() {
            s.disabled_reason = Some(if !permitted {
                "retry_not_authorized_or_incomplete_body"
            } else {
                "retry_budget_or_error"
            });
        }
        error.set_retry(retry);
        error
    }
}
