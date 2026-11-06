//! Bounded, verified HTTP transport shared by ACME and Cloudflare.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use std::{future::Future, path::Path, pin::Pin, time::Duration};

const MAX_RESPONSE: usize = 1024 * 1024;

pub fn client(root: Option<&Path>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    if let Some(path) = root {
        let pem = crate::files::read(path, 64 * 1024, false)?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| anyhow::anyhow!("invalid ACME trust root"))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("HTTP client initialization failed"))
}

pub async fn bounded(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("HTTP body read failed"))?
    {
        anyhow::ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE,
            "HTTP response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub struct Transport(pub reqwest::Client);

impl HttpClient for Transport {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body
                .collect()
                .await
                .map_err(|_| Error::from("ACME request encoding failed"))?
                .to_bytes();
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|_| Error::from("ACME transport failed"))?;
            let mut result = http::Response::builder().status(response.status());
            if let Some(headers) = result.headers_mut() {
                *headers = response.headers().clone();
            }
            let body = bounded(response)
                .await
                .map_err(|_| Error::from("ACME response read failed or exceeds limit"))?;
            Ok(BytesResponse::from(
                result.body(Full::new(Bytes::from(body)))?,
            ))
        })
    }
}
