//! Cloudflare control-plane transport and credentials. No proxy-path I/O.
#![forbid(unsafe_code)]
use anyhow::{Result, ensure};
use openssl::{rand::rand_bytes, symm};
use reqwest::{
    Method,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Deliberately has no Debug implementation. Never returned by an API.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub auth_type: String,
    pub secret: String,
    #[serde(default)]
    pub email: Option<String>,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.secret.zeroize();
        if let Some(email) = &mut self.email {
            email.zeroize();
        }
    }
}
impl Credentials {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (16..=512).contains(&self.secret.len())
                && self.secret.bytes().all(|b| b.is_ascii_graphic()),
            "invalid Cloudflare credential"
        );
        match self.auth_type.as_str() {
            "api_token" => ensure!(self.email.is_none(), "token does not use email"),
            "global_api_key" => {
                let email = self.email.as_deref().unwrap_or_default();
                ensure!(
                    (3..=254).contains(&email.len())
                        && email.contains('@')
                        && email.bytes().all(|b| b.is_ascii_graphic()),
                    "email required for global API key"
                );
            }
            _ => anyhow::bail!("unsupported Cloudflare authentication"),
        }
        Ok(())
    }
    pub fn headers(&self) -> Result<HeaderMap> {
        self.validate()?;
        let mut headers = HeaderMap::new();
        if self.auth_type == "api_token" {
            let value = Zeroizing::new(format!("Bearer {}", self.secret));
            let mut value = HeaderValue::from_str(&value)?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        } else {
            for (name, value) in [
                ("x-auth-key", self.secret.as_str()),
                ("x-auth-email", self.email.as_deref().unwrap_or_default()),
            ] {
                let mut value = HeaderValue::from_str(value)?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
        }
        Ok(headers)
    }
}

/// Versioned ACME input, separate from both legacy OWCF1 and database OWAD1.
pub fn seal(credentials: &Credentials, key: &[u8]) -> Result<Vec<u8>> {
    credentials.validate()?;
    ensure!(key.len() == 32, "invalid Cloudflare encryption key");
    let bytes = Zeroizing::new(serde_json::to_vec(credentials)?);
    let mut nonce = [0; 12];
    let mut tag = [0; 16];
    rand_bytes(&mut nonce)?;
    let encrypted = symm::encrypt_aead(
        symm::Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        b"openwaf-cloudflare-credentials-v1",
        &bytes,
        &mut tag,
    )?;
    Ok([b"OWCC1".as_slice(), &nonce, &tag, &encrypted].concat())
}
pub fn open(bytes: &[u8], key: &[u8]) -> Result<Credentials> {
    // Import operator-provisioned OWCF1 tokens using their original AAD.
    if bytes.starts_with(b"OWCF1") {
        ensure!(
            key.len() == 32 && (33..=4096).contains(&bytes.len()),
            "invalid Cloudflare envelope"
        );
        let plain = Zeroizing::new(
            symm::decrypt_aead(
                symm::Cipher::aes_256_gcm(),
                key,
                Some(&bytes[5..17]),
                b"openwaf-cloudflare-token-v1",
                &bytes[33..],
                &bytes[17..33],
            )
            .map_err(|_| anyhow::anyhow!("Cloudflare credential integrity check failed"))?,
        );
        let credentials = Credentials {
            auth_type: "api_token".into(),
            secret: std::str::from_utf8(&plain)
                .map_err(|_| anyhow::anyhow!("invalid Cloudflare token"))?
                .to_owned(),
            email: None,
        };
        credentials.validate()?;
        return Ok(credentials);
    }
    ensure!(
        key.len() == 32 && (33..=4096).contains(&bytes.len()) && &bytes[..5] == b"OWCC1",
        "invalid Cloudflare envelope"
    );
    let plain = Zeroizing::new(
        symm::decrypt_aead(
            symm::Cipher::aes_256_gcm(),
            key,
            Some(&bytes[5..17]),
            b"openwaf-cloudflare-credentials-v1",
            &bytes[33..],
            &bytes[17..33],
        )
        .map_err(|_| anyhow::anyhow!("Cloudflare credential integrity check failed"))?,
    );
    let credentials: Credentials = serde_json::from_slice(&plain)
        .map_err(|_| anyhow::anyhow!("invalid Cloudflare credentials"))?;
    credentials.validate()?;
    Ok(credentials)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiError {
    Denied,
    Limited,
    NotFound,
    Rejected,
    Unavailable,
    OutcomeUnknown,
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

pub struct Client {
    http: reqwest::Client,
    base: String,
    headers: HeaderMap,
}
impl Client {
    pub fn new(credentials: &Credentials) -> Result<Self> {
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(2);
        let base = "https://api.cloudflare.com/client/v4".to_owned();
        #[cfg(feature = "integration-test-provider")]
        let (builder, base) = if let Ok(base) = std::env::var("OPENWAF_TEST_CLOUDFLARE_API") {
            let url = reqwest::Url::parse(&base)?;
            ensure!(
                url.scheme() == "https"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/client/v4"
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "test provider must be local HTTPS"
            );
            let ca = std::fs::read(std::env::var("OPENWAF_TEST_CLOUDFLARE_CA")?)?;
            (
                builder.add_root_certificate(reqwest::Certificate::from_pem(&ca)?),
                base,
            )
        } else {
            (builder, base)
        };
        Ok(Self {
            http: builder.build()?,
            base,
            headers: credentials.headers()?,
        })
    }
    /// Path segments are constructed by callers from validated IDs only. No raw
    /// Cloudflare message/body/URL is exposed on failure. Writes are never retried.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> ApiResult<Value> {
        let write = method != Method::GET;
        let failure = || {
            if write {
                ApiError::OutcomeUnknown
            } else {
                ApiError::Unavailable
            }
        };
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .headers(self.headers.clone())
            .query(query);
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request.send().await.map_err(|_| failure())?;
        match response.status().as_u16() {
            401 | 403 => return Err(ApiError::Denied),
            404 => return Err(ApiError::NotFound),
            429 => return Err(ApiError::Limited),
            400..=499 => return Err(ApiError::Rejected),
            200..=299 => {}
            _ => return Err(failure()),
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| failure())? {
            if bytes.len() + chunk.len() > 512 * 1024 {
                return Err(failure());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| failure())?;
        if value["success"] != true {
            return Err(if write {
                ApiError::OutcomeUnknown
            } else {
                ApiError::Rejected
            });
        }
        if value.get("result").is_none_or(Value::is_null) {
            return Err(failure());
        }
        Ok(value)
    }
}
pub fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn response(method: Method, status: u16, body: &str) -> ApiResult<Value> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let text = format!(
            "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/should-not-follow\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut bytes = [0; 4096];
            let received = stream.read(&mut bytes).await.expect("request");
            assert!(received > 0);
            // Oversize-response tests may close the socket before all bytes drain.
            let _result = stream.write_all(text.as_bytes()).await;
        });
        let client = Client {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(1))
                .build()
                .expect("client"),
            base: format!("http://{address}"),
            headers: HeaderMap::new(),
        };
        let result = client.call(method, "/zones", &[], None).await;
        server.await.expect("owned fixture task");
        result
    }
    #[tokio::test]
    async fn bounded_transport_requires_acknowledgement_and_never_follows_redirects() {
        assert!(
            response(Method::GET, 200, r#"{"success":true,"result":[]}"#)
                .await
                .is_ok()
        );
        assert_eq!(
            response(Method::GET, 403, "provider detail must be discarded").await,
            Err(ApiError::Denied)
        );
        assert_eq!(
            response(Method::GET, 429, "rate limited").await,
            Err(ApiError::Limited)
        );
        assert_eq!(
            response(Method::GET, 302, "").await,
            Err(ApiError::Unavailable)
        );
        assert_eq!(
            response(Method::POST, 503, "").await,
            Err(ApiError::OutcomeUnknown)
        );
        assert_eq!(
            response(Method::PATCH, 200, r#"{"success":true}"#).await,
            Err(ApiError::OutcomeUnknown)
        );
        assert_eq!(
            response(Method::POST, 200, "invalid JSON").await,
            Err(ApiError::OutcomeUnknown)
        );
        assert_eq!(
            response(Method::GET, 200, &"x".repeat(512 * 1024 + 1)).await,
            Err(ApiError::Unavailable)
        );
    }
    #[test]
    fn credential_modes_and_envelope_are_bound_and_redacted() -> Result<()> {
        let mut key = [0; 32];
        rand_bytes(&mut key)?;
        for auth_type in ["api_token", "global_api_key"] {
            let c = Credentials {
                auth_type: auth_type.into(),
                secret: openssl::sha::sha256(&key)
                    .iter()
                    .map(|v| format!("{v:02x}"))
                    .collect(),
                email: (auth_type == "global_api_key").then(|| "operator@example.test".into()),
            };
            let h = c.headers()?;
            assert!(h.values().all(HeaderValue::is_sensitive));
            assert_eq!(h.contains_key(AUTHORIZATION), auth_type == "api_token");
            assert!(!format!("{h:?}").contains(&c.secret));
            let mut encrypted = seal(&c, &key)?;
            assert!(
                !encrypted
                    .windows(c.secret.len())
                    .any(|w| w == c.secret.as_bytes())
            );
            assert_eq!(open(&encrypted, &key)?.secret, c.secret);
            assert!(open(&encrypted, &[0; 32]).is_err());
            encrypted[20] ^= 1;
            assert!(open(&encrypted, &key).is_err());
        }
        Ok(())
    }
}
