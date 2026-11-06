//! A failed event stream is request-local once the upstream has served it.
//! Active probes continue to determine endpoint availability independently.
use pingora::{Error, ErrorSource, ErrorType, http::ResponseHeader};

#[derive(Default)]
pub struct Observation {
    successful_event_stream: bool,
}

impl Observation {
    pub fn response(&mut self, header: &ResponseHeader) {
        if header.status.is_informational() {
            return;
        }
        self.successful_event_stream = header.status.is_success()
            && header
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<mime::Mime>().ok())
                .is_some_and(|value| value.essence_str() == "text/event-stream");
    }

    pub fn failure(&self, error: &Error, peer: &openwaf_config::health::Peer) {
        if self.should_quarantine(error) {
            peer.fail();
        }
    }

    fn should_quarantine(&self, error: &Error) -> bool {
        error.esource() == &ErrorSource::Upstream
            && !(self.successful_event_stream
                && matches!(
                    error.etype(),
                    ErrorType::ReadError | ErrorType::ReadTimedout | ErrorType::ConnectionClosed
                ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream_error(kind: ErrorType) -> Box<Error> {
        let mut error = Error::new(kind);
        error.as_up();
        error
    }

    fn response(status: u16, content_type: &str) -> ResponseHeader {
        let mut response = ResponseHeader::build(status, None).expect("response");
        response
            .insert_header("content-type", content_type)
            .expect("content type");
        response
    }

    #[test]
    fn interrupted_successful_sse_does_not_quarantine_endpoint() {
        let mut health = Observation::default();
        health.response(&response(200, "text/event-stream; charset=utf-8"));
        for kind in [
            ErrorType::ReadError,
            ErrorType::ReadTimedout,
            ErrorType::ConnectionClosed,
        ] {
            assert!(!health.should_quarantine(&upstream_error(kind)));
        }
        // A connection/TLS failure is still endpoint evidence, even if an
        // unrelated response was previously observed by the caller.
        assert!(health.should_quarantine(&upstream_error(ErrorType::ConnectRefused)));
        assert!(health.should_quarantine(&upstream_error(ErrorType::TLSHandshakeFailure)));
    }

    #[test]
    fn pre_response_and_non_sse_failures_still_quarantine() {
        let error = upstream_error(ErrorType::ReadError);
        assert!(Observation::default().should_quarantine(&error));
        for (status, content_type) in [
            (200, "application/json"),
            (200, "text/event-stream-invalid"),
            (503, "text/event-stream"),
            (103, "text/event-stream"),
        ] {
            let mut health = Observation::default();
            health.response(&response(status, content_type));
            assert!(health.should_quarantine(&error));
        }
    }

    #[test]
    fn downstream_and_internal_errors_never_quarantine() {
        for source in [
            ErrorSource::Downstream,
            ErrorSource::Internal,
            ErrorSource::Unset,
        ] {
            let mut error = Error::new(ErrorType::ReadError);
            error.esource = source;
            assert!(!Observation::default().should_quarantine(&error));
        }
    }

    #[test]
    fn next_api_request_remains_routable_after_sse_disconnect() {
        use openwaf_config::{Context, Snapshot};
        use std::time::{Duration, Instant};

        let address = "127.0.0.1:9443".parse().expect("address");
        let document = serde_json::from_value(serde_json::json!({
            "routes": [{"id":"admin","hostname":"admin.test","path":"/","path_match":"prefix","upstream":"admin"}],
            "upstreams": [{"id":"admin","endpoints":[{"address":"127.0.0.1:9443","protocol":"http"}]}]
        })).expect("document");
        let snapshot = Snapshot::prepare(
            1,
            document,
            &Context {
                listeners: vec![],
                local_ips: vec![],
            },
        )
        .expect("snapshot");
        let publish = || {
            snapshot.health.publish(
                0,
                0,
                vec![address],
                Instant::now() + Duration::from_secs(15),
                1,
                "healthy",
            )
        };
        publish();
        let (_, _, peer) = snapshot.endpoint(0).expect("initial API endpoint");
        let mut sse = Observation::default();
        sse.response(&response(200, "text/event-stream"));
        sse.failure(&upstream_error(ErrorType::ReadError), &peer);
        assert!(
            snapshot.endpoint(0).is_some(),
            "SSE EOF must not cause the next API request to return 503"
        );

        Observation::default().failure(&upstream_error(ErrorType::ConnectRefused), &peer);
        assert!(
            snapshot.endpoint(0).is_none(),
            "a real endpoint failure still removes it"
        );
        publish();
        assert!(
            snapshot.endpoint(0).is_some(),
            "active health checks still recover failed peers"
        );
    }
}
