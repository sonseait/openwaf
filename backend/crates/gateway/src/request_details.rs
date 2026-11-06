//! Bounded request metadata. Unknown/sensitive headers and URL secrets are redacted
//! before entering a queue. No body contents, cookies or credentials are retained.
use http::{HeaderMap, Method, Uri, Version};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

pub const MAX_DETAILS_BYTES: usize = 16 * 1024;
pub const SCHEMA_VERSION: u8 = 9;
const MAX_HEADERS: usize = 24;
const MAX_HEADER_BYTES: usize = 2048;
const REDACTED: &str = "[REDACTED]";

#[derive(Default, Serialize)]
pub struct Headers {
    pub entries: Vec<Header>,
    pub total: usize,
    pub omitted: usize,
    pub truncated: bool,
}
#[derive(Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
    pub redacted: bool,
    pub truncated: bool,
}
/// Keep UTF-8 boundaries and remove control characters without allocating an
/// unbounded intermediate string. The boolean reports omitted/replaced data.
fn text(value: &str, max: usize) -> (String, bool) {
    let mut result = String::with_capacity(value.len().min(max));
    let mut changed = false;
    for c in value.chars() {
        let c = if c.is_control() {
            changed = true;
            ' '
        } else {
            c
        };
        if result.len() + c.len_utf8() > max {
            return (result, true);
        }
        result.push(c);
    }
    (result, changed)
}
/// Preserve HTTP destinations only; never retain userinfo, queries or fragments.
/// Reject ambiguous browser URL syntax rather than guessing how it is resolved.
fn sanitized_header_url(raw: &str) -> Option<String> {
    if raw.len() > 8192
        || raw.contains('\\')
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    let destination = raw.split(['?', '#']).next()?;
    if destination.starts_with('/') && !destination.starts_with("//") {
        let uri = destination.parse::<Uri>().ok()?;
        return (uri.scheme().is_none() && uri.authority().is_none())
            .then(|| destination.to_owned());
    }
    let (scheme, rest) = destination.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let boundary = rest.find('/').unwrap_or(rest.len());
    let authority = rest[..boundary].rsplit('@').next()?;
    let sanitized = format!("{scheme}://{authority}{}", &rest[boundary..]);
    let uri = sanitized.parse::<Uri>().ok()?;
    if uri.host().is_none_or(str::is_empty) {
        return None;
    }
    Some(sanitized)
}

impl Headers {
    pub fn capture(headers: &HeaderMap) -> Self {
        let mut out = Self {
            total: headers.len(),
            ..Default::default()
        };
        let mut remaining = MAX_HEADER_BYTES;
        for (name, value) in headers {
            if out.entries.len() == MAX_HEADERS || remaining < 96 {
                break;
            }
            let raw = value.to_str().ok();
            // Unknown application headers, credentials, identity and forwarding
            // values remain private. URL headers use a separate sanitizer below.
            let allowed = matches!(
                name.as_str(),
                "accept"
                    | "accept-encoding"
                    | "accept-language"
                    | "content-type"
                    | "content-length"
                    | "content-encoding"
                    | "user-agent"
                    | "range"
                    | "connection"
                    | "upgrade"
                    | "sec-websocket-version"
                    | "cache-control"
                    | "vary"
                    | "x-content-type-options"
                    | "referrer-policy"
                    | "host"
                    | "sec-fetch-site"
                    | "sec-fetch-mode"
                    | "sec-fetch-dest"
                    | "sec-fetch-user"
                    | "access-control-request-method"
                    | "access-control-request-headers"
                    | "access-control-allow-methods"
                    | "access-control-allow-headers"
                    | "access-control-allow-credentials"
                    | "access-control-max-age"
                    | "access-control-expose-headers"
                    | "x-request-id"
                    | "x-correlation-id"
                    | "traceparent"
                    | "date"
                    | "server"
                    | "allow"
                    | "retry-after"
            );
            let url_value = if matches!(
                name.as_str(),
                "referer" | "location" | "origin" | "access-control-allow-origin"
            ) {
                raw.and_then(|value| {
                    if matches!(value, "null" | "*")
                        && matches!(name.as_str(), "origin" | "access-control-allow-origin")
                    {
                        Some(value.to_owned())
                    } else {
                        sanitized_header_url(value)
                    }
                })
            } else {
                None
            };
            let visible = url_value.as_deref().or(if allowed { raw } else { None });
            let redacted = visible.is_none() || visible != raw;
            let (value, value_truncated) = text(
                visible.unwrap_or(REDACTED),
                256.min(remaining.saturating_sub(64)),
            );
            let (name, name_truncated) = text(name.as_str(), 64);
            remaining = remaining.saturating_sub(name.len() + value.len());
            out.truncated |= value_truncated || name_truncated;
            out.entries.push(Header {
                name,
                value,
                redacted,
                truncated: value_truncated || name_truncated,
            });
        }
        out.omitted = out.total.saturating_sub(out.entries.len());
        out.truncated |= out.omitted > 0;
        out
    }
}
#[derive(Default, Serialize)]
pub struct Client {
    pub ip: Option<IpAddr>,
    pub peer_ip: Option<IpAddr>,
    pub peer_port: Option<u16>,
    pub ip_source: &'static str,
    pub user_agent: Option<String>,
    pub user_agent_truncated: bool,
    pub country_code: Option<String>,
    pub geoip_status: &'static str,
    pub geoip_source: &'static str,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
}
#[derive(Default, Serialize)]
pub struct Request {
    pub method: String,
    pub scheme: &'static str,
    pub http_version: &'static str,
    pub host: Option<String>,
    pub path: String,
    pub path_truncated: bool,
    pub query: Option<&'static str>,
    pub headers: Headers,
    pub body_declared_bytes: Option<u64>,
    pub body_received_bytes: u64,
    pub body_read_complete: bool,
}
#[derive(Default, Serialize)]
pub struct Response {
    pub headers: Option<Headers>,
    pub body_declared_bytes: Option<u64>,
    pub body_sent_bytes: Option<u64>,
    pub upstream_body_received_bytes: u64,
    pub upstream_body_complete: bool,
    pub completed: bool,
}
#[derive(Default, Serialize)]
pub struct Capture {
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
    pub client: Client,
    pub request: Request,
    pub response: Response,
}
fn content_length(headers: &HeaderMap) -> Option<u64> {
    if headers.get_all("content-length").iter().count() != 1 {
        return None;
    }
    headers.get("content-length")?.to_str().ok()?.parse().ok()
}
impl Capture {
    pub fn new(
        method: &Method,
        uri: &Uri,
        version: Version,
        headers: &HeaderMap,
        tls: bool,
        peer: Option<SocketAddr>,
    ) -> Self {
        let (path, path_truncated) = text(uri.path(), 2048);
        let agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| text(v, 512));
        Self {
            started_at_unix_ms: openwaf_telemetry::now_ms(),
            client: Client {
                peer_ip: peer.map(|p| openwaf_config::normalized_ip(p.ip())),
                peer_port: peer.map(|p| p.port()),
                ip_source: "unresolved",
                geoip_status: "not_resolved",
                geoip_source: "maxmind-country",
                user_agent: agent.as_ref().map(|(v, _)| v.clone()),
                user_agent_truncated: agent.is_some_and(|(_, truncated)| truncated),
                ..Default::default()
            },
            request: Request {
                method: text(method.as_str(), 32).0,
                scheme: if tls { "https" } else { "http" },
                http_version: match version {
                    Version::HTTP_10 => "HTTP/1.0",
                    Version::HTTP_11 => "HTTP/1.1",
                    Version::HTTP_2 => "HTTP/2",
                    _ => "Unknown",
                },
                path,
                path_truncated,
                query: uri.query().map(|_| REDACTED),
                headers: Headers::capture(headers),
                body_declared_bytes: content_length(headers),
                // Use transport body state, including HTTP/2 END_STREAM.
                body_read_complete: false,
                ..Default::default()
            },
            ..Default::default()
        }
    }
    pub fn tls(&mut self, version: &str, cipher: &str) {
        self.client.tls_version = Some(text(version, 64).0);
        self.client.tls_cipher = Some(text(cipher, 128).0);
    }
    pub fn response_headers(&mut self, headers: &HeaderMap) {
        self.response.body_declared_bytes = content_length(headers);
        self.response.headers = Some(Headers::capture(headers));
    }
    pub fn received(&mut self, bytes: u64, end: bool) {
        self.request.body_received_bytes = self.request.body_received_bytes.max(bytes);
        self.request.body_read_complete |= end
            && self
                .request
                .body_declared_bytes
                .is_none_or(|declared| self.request.body_received_bytes >= declared);
    }
}

/// Keep each details payload below the SSE line budget even for adversarial
/// metadata. Decisions/attempts retain their existing bounded contracts.
pub fn serialize(mut value: serde_json::Value) -> String {
    let encoded = value.to_string();
    if encoded.len() <= MAX_DETAILS_BYTES {
        return encoded;
    }
    value["metadata"]["request"]["headers"] = serde_json::Value::Null;
    value["metadata"]["response"]["headers"] = serde_json::Value::Null;
    value["metadata_truncated"] = true.into();
    let encoded = value.to_string();
    if encoded.len() <= MAX_DETAILS_BYTES {
        return encoded;
    }
    // Enforce a hard ceiling if a future decision field loses its bound.
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "metadata_truncated": true,
        "details_truncated": true,
        "outcome": "details_limit_exceeded"
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_headers_keep_destination_without_credentials_query_or_fragment() {
        for (name, input, expected) in [
            (
                "referer",
                "https://user:private-marker@example.test/page?token=private-marker#private-marker",
                "https://example.test/page",
            ),
            (
                "location",
                "/login?token=private-marker#private-marker",
                "/login",
            ),
            ("origin", "https://example.test", "https://example.test"),
            (
                "location",
                "https://example.test/a",
                "https://example.test/a",
            ),
            ("referer", "malformed-private-marker", REDACTED),
            ("location", "javascript:private-marker", REDACTED),
            ("location", "//private-marker@example.test/a", REDACTED),
            ("location", "https://example.test\\private-marker", REDACTED),
            ("origin", "null", "null"),
            ("access-control-allow-origin", "*", "*"),
            (
                "location",
                "https://[::1]:8443/a?private-marker",
                "https://[::1]:8443/a",
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name, input.parse().expect("header"));
            let captured = Headers::capture(&headers);
            assert_eq!(captured.entries[0].value, expected, "{name}");
            assert_eq!(captured.entries[0].redacted, input != expected);
            assert!(
                !serde_json::to_string(&captured)
                    .expect("json")
                    .contains("private-marker")
            );
        }
    }
    #[test]
    fn diagnostic_headers_are_visible_but_credentials_remain_private() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("host", "example.test:8443"),
            ("origin", "https://example.test"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
            ("sec-fetch-dest", "empty"),
            ("access-control-request-method", "POST"),
            (
                "access-control-request-headers",
                "authorization,content-type",
            ),
            ("x-request-id", "request-123"),
        ] {
            headers.insert(name, value.parse().expect("header"));
        }
        for name in [
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-csrf-token",
            "remote-user",
            "x-custom-token",
            "x-unknown",
        ] {
            headers.insert(name, "private-marker".parse().expect("header"));
        }
        let captured = Headers::capture(&headers);
        for entry in &captured.entries {
            if entry.value == REDACTED {
                assert!(entry.redacted);
            } else {
                assert!(!entry.redacted, "{}", entry.name);
            }
        }
        assert_eq!(
            captured
                .entries
                .iter()
                .find(|h| h.name == "host")
                .expect("host")
                .value,
            "example.test:8443"
        );
        assert_eq!(
            captured
                .entries
                .iter()
                .find(|h| h.name == "sec-fetch-mode")
                .expect("mode")
                .value,
            "cors"
        );
        assert!(
            !serde_json::to_string(&captured)
                .expect("json")
                .contains("private-marker")
        );
    }
    #[test]
    fn secrets_are_redacted_and_payload_is_bounded() {
        let mut headers = HeaderMap::new();
        for name in [
            "authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "referer",
            "location",
            "forwarded",
        ] {
            headers.insert(name, "sensitive-marker".parse().expect("header"));
        }
        headers.insert("user-agent", "OpenWAF-Test/1.0".parse().expect("header"));
        headers.insert("content-length", "42".parse().expect("header"));
        let uri: Uri = "/checkout?token=sensitive-marker".parse().expect("uri");
        let capture = Capture::new(
            &Method::POST,
            &uri,
            Version::HTTP_2,
            &headers,
            true,
            Some("[::1]:1234".parse().expect("peer")),
        );
        let json = serde_json::to_string(&capture).expect("serialize");
        assert!(!json.contains("sensitive-marker"));
        assert!(json.contains("OpenWAF-Test/1.0"));
        assert_eq!(capture.request.path, "/checkout");
        assert_eq!(capture.request.body_declared_bytes, Some(42));
        assert!(!capture.request.body_read_complete);
        assert_eq!(capture.request.http_version, "HTTP/2");
        for n in 0..100 {
            headers.append(
                http::header::HeaderName::from_bytes(format!("x-test-{n}").as_bytes())
                    .expect("name"),
                "secret".parse().expect("header"),
            );
        }
        headers.insert("user-agent", "x".repeat(20000).parse().expect("header"));
        let mut capture = Capture::new(&Method::GET, &uri, Version::HTTP_11, &headers, false, None);
        capture.response_headers(&headers);
        assert!(capture.request.headers.truncated);
        assert!(capture.request.headers.omitted > 0);
        assert!(capture.client.user_agent_truncated);
        assert!(serialize(serde_json::json!({"metadata":capture})).len() < MAX_DETAILS_BYTES);
    }
    #[test]
    fn hard_ceiling_survives_escaped_metadata_and_future_fields() {
        let headers = HeaderMap::new();
        let uri: Uri = format!("/{}", "%22".repeat(2000)).parse().expect("uri");
        let mut capture = Capture::new(&Method::POST, &uri, Version::HTTP_2, &headers, true, None);
        assert!(!capture.request.body_read_complete);
        capture.client.user_agent = Some("\"".repeat(512));
        let encoded = serialize(
            serde_json::json!({"schema_version":4,"metadata":capture,"future_field":"x".repeat(32000)}),
        );
        assert!(encoded.len() <= MAX_DETAILS_BYTES);
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("json");
        assert_eq!(value["details_truncated"], true);
    }
    #[test]
    fn utf8_truncation_and_observed_body_are_honest() {
        let (value, truncated) = text(&"é".repeat(1000), 511);
        assert_eq!(value.len(), 510);
        assert!(truncated);
        let mut capture = Capture::default();
        capture.received(50, false);
        capture.received(20, false);
        assert_eq!(capture.request.body_received_bytes, 50);
        assert!(!capture.request.body_read_complete);
        capture.request.body_declared_bytes = Some(100);
        capture.received(50, true);
        assert!(!capture.request.body_read_complete);
        capture.received(100, true);
        assert!(capture.request.body_read_complete);
    }
}
