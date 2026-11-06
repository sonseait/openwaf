//! Async, bounded ForwardAuth HTTP/1 exchange over already resolved health state.
//! No ambient proxy, redirect following, body forwarding, retry or background tasks.
use http::{HeaderMap, HeaderName};
use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use openwaf_config::{Endpoint, Protocol, middleware::ForwardAuth};
use pingora::http::RequestHeader;
use std::{net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
};

const LIMIT: usize = 16 * 1024;
pub struct Client {
    tls: SslConnector,
    permits: Semaphore,
}
pub struct Original<'a> {
    pub header: &'a RequestHeader,
    pub host: &'a str,
    pub client: std::net::IpAddr,
    pub tls: bool,
}
pub struct Reply {
    pub status: u16,
    pub identity: HeaderMap,
    pub headers: HeaderMap,
}
#[derive(Debug)]
pub enum Error {
    Capacity,
    Unavailable,
}
impl Client {
    /// Called once at gateway startup. TLS verification cannot be disabled by a route.
    pub fn new(ca: Option<&[X509]>) -> anyhow::Result<Self> {
        let mut tls = SslConnector::builder(SslMethod::tls_client())?;
        tls.set_verify(SslVerifyMode::PEER);
        tls.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        tls.set_default_verify_paths()?;
        tls.set_alpn_protos(b"\x08http/1.1")?;
        if let Some(ca) = ca {
            for cert in ca {
                tls.cert_store_mut().add_cert(cert.clone())?;
            }
        }
        Ok(Self {
            tls: tls.build(),
            permits: Semaphore::new(32),
        })
    }
    pub async fn check(
        &self,
        endpoint: &Endpoint,
        address: SocketAddr,
        policy: &ForwardAuth,
        original: Original<'_>,
    ) -> Result<Reply, Error> {
        let _permit = self.permits.try_acquire().map_err(|_| Error::Capacity)?;
        tokio::time::timeout(
            Duration::from_millis(policy.timeout_ms),
            self.exchange(endpoint, address, policy, original),
        )
        .await
        .map_err(|_| Error::Unavailable)?
    }
    async fn exchange(
        &self,
        endpoint: &Endpoint,
        address: SocketAddr,
        policy: &ForwardAuth,
        original: Original<'_>,
    ) -> Result<Reply, Error> {
        let mut fields = HeaderMap::new();
        for name in &policy.request_headers {
            for value in original.header.headers.get_all(name) {
                fields.append(
                    name.parse::<HeaderName>().map_err(|_| Error::Unavailable)?,
                    value.clone(),
                );
            }
        }
        let scheme = if original.tls { "https" } else { "http" };
        for (name, value) in [
            ("x-forwarded-method", original.header.method.to_string()),
            (
                "x-forwarded-uri",
                original
                    .header
                    .uri
                    .path_and_query()
                    .map_or("/", |v| v.as_str())
                    .to_owned(),
            ),
            ("x-forwarded-proto", scheme.into()),
            ("x-forwarded-host", original.host.into()),
            ("x-forwarded-for", original.client.to_string()),
            ("x-real-ip", original.client.to_string()),
            ("x-openwaf-hop", "1".into()),
        ] {
            fields.insert(name, value.parse().map_err(|_| Error::Unavailable)?);
        }
        // Request Host belongs to the auth service, original application Host is forwarded separately.
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\n",
            policy.path,
            String::from(endpoint.address.clone())
        )
        .into_bytes();
        for (name, value) in &fields {
            request.extend_from_slice(name.as_str().as_bytes());
            request.extend_from_slice(b": ");
            request.extend_from_slice(value.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"\r\n");
        if request.len() > LIMIT {
            return Err(Error::Unavailable);
        }
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|_| Error::Unavailable)?;
        let response = if endpoint.protocol == Protocol::Https {
            let name = endpoint
                .tls_server_name
                .as_deref()
                .ok_or(Error::Unavailable)?;
            let ssl = self
                .tls
                .configure()
                .and_then(|mut c| {
                    c.set_verify_hostname(endpoint.tls_verify);
                    if !endpoint.tls_verify {
                        c.set_verify(openssl::ssl::SslVerifyMode::NONE);
                    }
                    c.into_ssl(name)
                })
                .map_err(|_| Error::Unavailable)?;
            let mut stream =
                tokio_openssl::SslStream::new(ssl, tcp).map_err(|_| Error::Unavailable)?;
            Pin::new(&mut stream)
                .connect()
                .await
                .map_err(|_| Error::Unavailable)?;
            exchange_headers(&mut stream, &request).await?
        } else {
            let mut stream = tcp;
            exchange_headers(&mut stream, &request).await?
        };
        parse(&response, policy)
    }
}
async fn exchange_headers<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    stream
        .write_all(request)
        .await
        .map_err(|_| Error::Unavailable)?;
    let mut bytes = vec![0; LIMIT];
    let mut filled = 0;
    loop {
        if filled == LIMIT {
            return Err(Error::Unavailable);
        }
        let read = stream
            .read(&mut bytes[filled..])
            .await
            .map_err(|_| Error::Unavailable)?;
        if read == 0 {
            return Err(Error::Unavailable);
        }
        filled += read;
        if let Some(end) = bytes[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            bytes.truncate(end + 4);
            return Ok(bytes);
        }
    }
}
fn parse(bytes: &[u8], policy: &ForwardAuth) -> Result<Reply, Error> {
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut storage);
    if !response.parse(bytes).is_ok_and(|s| s.is_complete()) {
        return Err(Error::Unavailable);
    }
    let status = response.code.ok_or(Error::Unavailable)?;
    if !(200..=399).contains(&status) && status != 401 && status != 403 {
        return Err(Error::Unavailable);
    }
    let mut fields = HeaderMap::new();
    for field in response.headers {
        fields.append(
            field
                .name
                .parse::<HeaderName>()
                .map_err(|_| Error::Unavailable)?,
            field.value.try_into().map_err(|_| Error::Unavailable)?,
        );
    }
    if fields.get_all("content-length").iter().count() > 1
        || (fields.contains_key("content-length") && fields.contains_key("transfer-encoding"))
    {
        return Err(Error::Unavailable);
    }
    let nominated: Vec<_> = fields
        .get_all("connection")
        .iter()
        .map(|v| v.to_str().unwrap_or(""))
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    if nominated.iter().any(|n| {
        policy.response_headers.contains(n)
            || ["set-cookie", "location", "www-authenticate"].contains(&n.as_str())
    }) {
        return Err(Error::Unavailable);
    }
    let mut identity = HeaderMap::new();
    let mut headers = HeaderMap::new();
    if (200..300).contains(&status) {
        for name in &policy.response_headers {
            let mut values = fields.get_all(name).iter();
            if let Some(value) = values.next() {
                if values.next().is_some() {
                    return Err(Error::Unavailable);
                }
                identity.insert(
                    name.parse::<HeaderName>().map_err(|_| Error::Unavailable)?,
                    value.clone(),
                );
            }
        }
    } else if (300..400).contains(&status) {
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(Error::Unavailable);
        }
        let value = openwaf_config::middleware::single(&fields, "location")
            .map_err(|_| Error::Unavailable)?
            .filter(|v| policy.permits_redirect(v))
            .ok_or(Error::Unavailable)?;
        headers.insert("location", value.parse().map_err(|_| Error::Unavailable)?);
    }
    if status == 401 {
        for value in fields.get_all("www-authenticate") {
            headers.append("www-authenticate", value.clone());
        }
    }
    for cookie in fields.get_all("set-cookie") {
        let value = cookie.to_str().map_err(|_| Error::Unavailable)?;
        let name = value
            .split_once('=')
            .map(|v| v.0)
            .ok_or(Error::Unavailable)?;
        if policy.response_cookies.iter().any(|n| n == name) {
            headers.append("set-cookie", cookie.clone());
        }
    }
    Ok(Reply {
        status,
        identity,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> ForwardAuth {
        ForwardAuth {
            upstream: "auth".into(),
            response_headers: vec!["remote-user".into()],
            response_cookies: vec!["sso".into()],
            redirect_origins: vec!["https://login.test".into()],
            ..Default::default()
        }
    }
    #[test]
    fn auth_allows_only_verified_fields_and_selected_cookies() {
        let reply=parse(b"HTTP/1.1 200 OK\r\nRemote-User: verified\r\nX-Other: ignored\r\nSet-Cookie: sso=updated; Secure; HttpOnly; Path=/\r\nSet-Cookie: ignored=value\r\nContent-Length: 0\r\n\r\n",&policy()).unwrap();
        assert_eq!(reply.identity["remote-user"], "verified");
        assert!(!reply.identity.contains_key("x-other"));
        assert_eq!(reply.headers.get_all("set-cookie").iter().count(), 1);
        let reply=parse(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=login\r\nRemote-User: forged\r\nContent-Length: 0\r\n\r\n",&policy()).unwrap();
        assert!(reply.identity.is_empty());
        assert!(reply.headers.contains_key("www-authenticate"));
    }
    #[test]
    fn auth_never_turns_protocol_errors_or_untrusted_redirects_into_allow() {
        for bytes in [
            b"HTTP/1.1 500 Error\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nRemote-User: a\r\nRemote-User: b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nConnection: Remote-User\r\nRemote-User: a\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.test/\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: https://login.test/\r\nLocation: /other\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(parse(bytes, &policy()).is_err());
        }
        let reply = parse(
            b"HTTP/1.1 302 Found\r\nLocation: https://login.test/login?next=%2F\r\n\r\n",
            &policy(),
        )
        .unwrap();
        assert_eq!(reply.status, 302);
        assert_eq!(
            reply.headers["location"],
            "https://login.test/login?next=%2F"
        );
    }
}
