//! Cloudflare DNS-01. At most two durable leases, never delete unrelated TXT.
use crate::{
    files::{self, SecretKind},
    http,
};
use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    Client, Method, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub zone_id: String,
    pub zone_name: String,
    pub token_file: PathBuf,
    #[serde(default = "default_propagation")]
    pub propagation_seconds: u64,
    #[serde(default)]
    pub resolver: Option<SocketAddr>,
    #[cfg(feature = "integration-test-provider")]
    #[serde(default)]
    pub test_api: Option<TestApi>,
}

#[cfg(feature = "integration-test-provider")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestApi {
    base_url: String,
    ca_pem: PathBuf,
}

fn default_propagation() -> u64 {
    60
}
fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Config {
    pub fn validate(&mut self, hostname: &str) -> Result<()> {
        self.zone_name = self
            .zone_name
            .strip_suffix('.')
            .unwrap_or(&self.zone_name)
            .to_ascii_lowercase();
        ensure!(
            crate::dns_name(&self.zone_name),
            "invalid Cloudflare zone name"
        );
        ensure!(
            valid_id(&self.zone_id),
            "Cloudflare zone ID must contain 32 hex characters"
        );
        let name = hostname.strip_prefix("*.").unwrap_or(hostname);
        ensure!(
            name == self.zone_name || name.ends_with(&format!(".{}", self.zone_name)),
            "hostname is outside configured Cloudflare zone"
        );
        ensure!(
            (5..=120).contains(&self.propagation_seconds),
            "DNS propagation deadline must be 5..120 seconds"
        );
        if let Some(address) = self.resolver {
            ensure!(
                !address.ip().is_unspecified() && address.port() != 0,
                "invalid DNS resolver address"
            );
        }
        #[cfg(feature = "integration-test-provider")]
        if let Some(test) = &self.test_api {
            let url = reqwest::Url::parse(&test.base_url).context("invalid test provider URL")?;
            ensure!(
                url.scheme() == "https"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/client/v4",
                "test provider must be local HTTPS /client/v4"
            );
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    schema_version: u32,
    zone_id: String,
    zone_name: String,
    name: String,
    content: String,
    comment: String,
    record_id: Option<String>,
}

#[derive(Deserialize)]
struct Record {
    id: String,
    name: String,
    content: String,
    #[serde(rename = "type")]
    kind: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    result: Option<T>,
}

#[derive(Deserialize)]
struct PageInfo {
    total_pages: usize,
}
#[derive(Deserialize)]
struct ListEnvelope {
    success: bool,
    result: Vec<Record>,
    result_info: PageInfo,
}
#[derive(Deserialize)]
struct Deleted {
    id: String,
}

pub struct Cloudflare {
    client: Client,
    headers: HeaderMap,
    base: String,
    zone_id: String,
    zone_name: String,
    journal: PathBuf,
    key: Zeroizing<Vec<u8>>,
    leases: Vec<Lease>,
    resolver: crate::propagation::Checker,
    propagation: Duration,
}

impl Cloudflare {
    pub fn open(config: &Config, state: &Path, master_key: &Path) -> Result<Self> {
        let key = Zeroizing::new(files::read(master_key, 32, true)?);
        ensure!(
            key.len() == 32,
            "master key must contain exactly 32 raw bytes"
        );
        let encrypted = files::read(&config.token_file, 4096, true)?;
        let headers = if encrypted.starts_with(b"OWCC1") {
            openwaf_cloudflare::open(&encrypted, &key)?.headers()?
        } else {
            // Preserve existing operator-provisioned token files.
            let token = files::unseal_kind(&encrypted, &key, SecretKind::CloudflareToken)?;
            validate_token(&token)?;
            let mut authorization =
                HeaderValue::from_bytes(&[b"Bearer ".as_slice(), &token].concat())
                    .map_err(|_| anyhow::anyhow!("invalid Cloudflare token header"))?;
            authorization.set_sensitive(true);
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, authorization);
            headers
        };
        let base = "https://api.cloudflare.com/client/v4".to_owned();
        let client = http::client(None)?;
        #[cfg(feature = "integration-test-provider")]
        let (base, client) = if let Some(test) = &config.test_api {
            (test.base_url.clone(), http::client(Some(&test.ca_pem))?)
        } else {
            (base, client)
        };
        let journal = state.join("dns-lease.enc");
        let leases = if journal.try_exists()? {
            let plaintext = files::unseal_kind(
                &files::read(&journal, 16384, true)?,
                &key,
                SecretKind::DnsLease,
            )?;
            // Read the v1 single-lease journal during upgrades too.
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Saved {
                Many(Vec<Lease>),
                One(Lease),
            }
            let leases = match serde_json::from_slice(&plaintext)
                .map_err(|_| anyhow::anyhow!("invalid DNS cleanup journal"))?
            {
                Saved::Many(leases) => leases,
                Saved::One(lease) => vec![lease],
            };
            ensure!(
                !leases.is_empty()
                    && leases.len() <= 2
                    && leases.iter().all(|saved| saved.schema_version == 1
                        && saved.zone_id == config.zone_id
                        && saved.zone_name == config.zone_name
                        && valid_lease(saved)),
                "DNS cleanup journal does not match configured zone or schema"
            );
            leases
        } else {
            Vec::new()
        };
        let resolver = crate::propagation::Checker::new(config.resolver)?;
        Ok(Self {
            client,
            headers,
            base,
            zone_id: config.zone_id.clone(),
            zone_name: config.zone_name.clone(),
            journal,
            key,
            leases,
            resolver,
            propagation: Duration::from_secs(config.propagation_seconds),
        })
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/zones/{}/dns_records{suffix}", self.base, self.zone_id)
    }

    fn save(&self) -> Result<()> {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&self.leases).context("cannot encode DNS leases")?);
        files::replace_secret(
            &self.journal,
            &files::seal_kind(&plaintext, &self.key, SecretKind::DnsLease)?,
        )
    }

    fn clear(&mut self) -> Result<()> {
        self.leases.pop().context("no DNS lease to clear")?;
        if !self.leases.is_empty() {
            return self.save();
        }
        std::fs::remove_file(&self.journal).context("cannot remove DNS cleanup journal")?;
        files::sync_dir(
            self.journal
                .parent()
                .context("invalid DNS journal directory")?,
        )?;
        Ok(())
    }

    async fn send(&self, method: Method, suffix: &str) -> Result<reqwest::Response> {
        self.client
            .request(method, self.url(suffix))
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Cloudflare transport failed"))
    }

    pub async fn present(&mut self, hostname: &str, content: &str) -> Result<()> {
        ensure!(
            self.leases.len() < 2 && self.leases.iter().all(|lease| lease.record_id.is_some()),
            "pending DNS cleanup must finish before a new challenge"
        );
        let name = format!(
            "_acme-challenge.{}",
            hostname.strip_prefix("*.").unwrap_or(hostname)
        );
        self.leases.push(Lease {
            schema_version: 1,
            zone_id: self.zone_id.clone(),
            zone_name: self.zone_name.clone(),
            name,
            content: content.to_owned(),
            comment: format!("openwaf-acme:{}", files::random_id()?),
            record_id: None,
        });
        ensure!(
            self.leases.last().is_some_and(valid_lease),
            "invalid DNS challenge metadata"
        );
        // Durable intent BEFORE POST: timeout/signal may hide successful creation.
        self.save()?;
        let lease = self.leases.last().context("DNS lease missing")?;
        // DNS-01 has 43 base64url characters: one quoted TXT character-string
        // needs no escaping and stays below the 255-octet DNS limit.
        let body = serde_json::to_vec(
            &serde_json::json!({"type":"TXT", "name":lease.name, "content":format!("\"{}\"", lease.content), "ttl":60, "comment":lease.comment}),
        )?;
        let response = self
            .client
            .post(self.url(""))
            .headers(self.headers.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| {
                anyhow::anyhow!("Cloudflare create outcome unknown; cleanup journal retained")
            })?;
        let status = response.status();
        if status.is_client_error() && status != StatusCode::REQUEST_TIMEOUT {
            // An explicit rejection cannot have created our record.
            self.clear()?;
            return status_error(status);
        }
        check_status(status)?;
        let envelope: Envelope<Record> = decode(response).await?;
        if !envelope.success {
            self.clear()?;
            bail!("Cloudflare API rejected TXT creation");
        }
        let record = envelope
            .result
            .context("Cloudflare create response has no record")?;
        ensure!(
            valid_id(&record.id),
            "Cloudflare returned invalid record ID; cleanup required"
        );
        // Keep the returned ID even on bad metadata, but cleanup GET must verify
        // all ownership fields before allowing DELETE.
        self.leases
            .last_mut()
            .context("DNS lease missing")?
            .record_id = Some(record.id.clone());
        self.save()?;
        ensure!(
            self.leases
                .last()
                .is_some_and(|lease| matches_record(lease, &record)),
            "Cloudflare created record metadata mismatch; cleanup required"
        );
        eprintln!("Cloudflare DNS challenge created");
        Ok(())
    }

    pub async fn wait_propagation(&self) -> Result<()> {
        let lease = self
            .leases
            .last()
            .context("no DNS challenge for propagation")?;
        self.resolver
            .wait(&lease.name, &lease.content, self.propagation)
            .await
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        while !self.leases.is_empty() {
            self.cleanup_one().await?;
        }
        Ok(())
    }
    async fn cleanup_one(&mut self) -> Result<()> {
        let lease = self.leases.last().context("no DNS lease to clean")?;
        let id = if let Some(id) = &lease.record_id {
            id.clone()
        } else {
            // Never list/delete the entire zone. Name/type filter plus exact
            // content + random ownership comment identifies an ambiguous POST.
            let response = self
                .client
                .get(self.url(""))
                .headers(self.headers.clone())
                .query(&[
                    ("type", "TXT"),
                    ("name", lease.name.as_str()),
                    ("per_page", "100"),
                    ("page", "1"),
                ])
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("Cloudflare cleanup lookup failed"))?;
            check_status(response.status())?;
            let page: ListEnvelope = decode(response).await?;
            ensure!(
                page.success && page.result.len() <= 100 && page.result_info.total_pages <= 1,
                "Cloudflare cleanup lookup incomplete; journal retained"
            );
            let records = page
                .result
                .iter()
                .filter(|record| matches_record(lease, record))
                .collect::<Vec<_>>();
            ensure!(
                records.len() == 1,
                "Cloudflare create outcome ambiguous; journal retained for reconciliation"
            );
            ensure!(
                valid_id(&records[0].id),
                "invalid Cloudflare cleanup record ID"
            );
            records[0].id.clone()
        };
        // Persist a recovered ID before DELETE as well: a lost delete response
        // can then be reconciled via an acknowledged record-not-found response.
        self.leases
            .last_mut()
            .context("DNS lease missing")?
            .record_id = Some(id.clone());
        self.save()?;
        let response = self.send(Method::GET, &format!("/{id}")).await?;
        if response.status() == StatusCode::NOT_FOUND {
            require_record_missing(response).await?;
            self.clear()?;
            return Ok(());
        }
        check_status(response.status())?;
        let envelope: Envelope<Record> = decode(response).await?;
        let record = envelope
            .result
            .filter(|_| envelope.success)
            .context("Cloudflare cleanup record lookup rejected")?;
        ensure!(
            record.id == id
                && self
                    .leases
                    .last()
                    .is_some_and(|lease| matches_record(lease, &record)),
            "Cloudflare record ownership changed; refusing deletion"
        );
        let response = self.send(Method::DELETE, &format!("/{id}")).await?;
        if response.status() == StatusCode::NOT_FOUND {
            require_record_missing(response).await?;
        } else {
            check_status(response.status())?;
            let envelope: Envelope<Deleted> = decode(response).await?;
            ensure!(
                envelope.success && envelope.result.is_some_and(|record| record.id == id),
                "Cloudflare deletion not acknowledged; journal retained"
            );
        }
        self.clear()?;
        eprintln!("Cloudflare DNS cleanup completed");
        Ok(())
    }
}

fn valid_lease(lease: &Lease) -> bool {
    let Some(name) = lease.name.strip_prefix("_acme-challenge.") else {
        return false;
    };
    let marker = lease.comment.strip_prefix("openwaf-acme:");
    crate::dns_name(name)
        && (name == lease.zone_name || name.ends_with(&format!(".{}", lease.zone_name)))
        && lease.content.len() == 43
        && lease
            .content
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && marker.is_some_and(valid_id)
        && lease.record_id.as_deref().is_none_or(valid_id)
}

fn matches_record(lease: &Lease, record: &Record) -> bool {
    record.kind == "TXT"
        && record.name.eq_ignore_ascii_case(&lease.name)
        && txt_matches(&record.content, &lease.content)
        && record.comment.as_deref() == Some(&lease.comment)
}

/// Compare bounded TXT presentation by decoded value, without allocating output.
fn txt_matches(presentation: &str, expected: &str) -> bool {
    if presentation == expected {
        return true;
    }
    let input = presentation.as_bytes();
    if input.len() > 512 || input.first() != Some(&b'"') {
        return false;
    }
    let mut index = 0;
    let mut matched = 0;
    while index < input.len() {
        while input.get(index).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            index += 1;
        }
        if index == input.len() {
            break;
        }
        if input[index] != b'"' {
            return false;
        }
        index += 1;
        loop {
            let Some(&byte) = input.get(index) else {
                return false;
            };
            index += 1;
            if byte == b'"' {
                break;
            }
            let decoded = if byte == b'\\' {
                let Some(&next) = input.get(index) else {
                    return false;
                };
                index += 1;
                if next.is_ascii_digit() {
                    let Some(digits) = input.get(index..index + 2) else {
                        return false;
                    };
                    if !digits.iter().all(u8::is_ascii_digit) {
                        return false;
                    }
                    let value = u16::from(next - b'0') * 100
                        + u16::from(digits[0] - b'0') * 10
                        + u16::from(digits[1] - b'0');
                    let Ok(value) = u8::try_from(value) else {
                        return false;
                    };
                    index += 2;
                    value
                } else {
                    next
                }
            } else {
                byte
            };
            if expected.as_bytes().get(matched) != Some(&decoded) {
                return false;
            }
            matched += 1;
        }
    }
    matched == expected.len()
}

pub fn validate_token(bytes: &[u8]) -> Result<()> {
    ensure!(
        (16..=512).contains(&bytes.len()) && bytes.iter().all(|byte| byte.is_ascii_graphic()),
        "invalid Cloudflare token format"
    );
    Ok(())
}

fn check_status(status: StatusCode) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        status_error(status)
    }
}
fn status_error(status: StatusCode) -> Result<()> {
    match status.as_u16() {
        401 | 403 => bail!("Cloudflare authentication or zone permission denied"),
        429 => bail!("Cloudflare rate limited; retry later"),
        code => bail!("Cloudflare API unavailable or rejected request (HTTP {code})"),
    }
}
async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    serde_json::from_slice(&http::bounded(response).await?)
        .map_err(|_| anyhow::anyhow!("invalid Cloudflare response schema"))
}

async fn require_record_missing(response: reqwest::Response) -> Result<()> {
    #[derive(Deserialize)]
    struct ApiError {
        code: u64,
    }
    #[derive(Deserialize)]
    struct Missing {
        success: bool,
        errors: Vec<ApiError>,
    }
    let response: Missing = decode(response).await?;
    ensure!(
        !response.success && response.errors.iter().any(|error| error.code == 81044),
        "Cloudflare 404 does not acknowledge missing DNS record; journal retained"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_requires_exact_record_and_random_marker() {
        let lease = Lease {
            schema_version: 1,
            zone_id: "a".repeat(32),
            zone_name: "example.test".into(),
            name: "_acme-challenge.example.test".into(),
            content: "x".repeat(43),
            comment: format!("openwaf-acme:{}", "b".repeat(32)),
            record_id: None,
        };
        assert!(valid_lease(&lease));
        let mut record = Record {
            id: "c".repeat(32),
            name: lease.name.clone(),
            content: lease.content.clone(),
            kind: "TXT".into(),
            comment: None,
        };
        assert!(!matches_record(&lease, &record));
        record.comment = Some(lease.comment.clone());
        assert!(matches_record(&lease, &record));
        record.content.push('x');
        assert!(!matches_record(&lease, &record));
    }

    #[test]
    fn configuration_limits_zone_scope_and_test_endpoint() -> Result<()> {
        let base = serde_json::json!({"zone_id":"a".repeat(32), "zone_name":"Example.Test.", "token_file":"token.enc"});
        let mut config: Config = serde_json::from_value(base.clone())?;
        assert!(config.validate("*.app.example.test").is_ok());
        assert!(config.validate("evil-example.test").is_err());
        config.propagation_seconds = 121;
        assert!(config.validate("app.example.test").is_err());
        let mut injected = base;
        injected["test_api"] = serde_json::json!({"base_url":"https://attacker.example/client/v4", "ca_pem":"root.pem"});
        #[cfg(not(feature = "integration-test-provider"))]
        assert!(serde_json::from_value::<Config>(injected).is_err());
        #[cfg(feature = "integration-test-provider")]
        assert!(
            serde_json::from_value::<Config>(injected)?
                .validate("app.example.test")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn txt_presentation_matches_value_and_rejects_malformed_input() {
        for value in [
            "abc-_123",
            "\"abc-_123\"",
            "\"abc\" \"-_123\"",
            "\"\\097bc-_123\"",
        ] {
            assert!(txt_matches(value, "abc-_123"));
        }
        for value in [
            "\"abc-_123",
            "\"abc-_123\" junk",
            "\"abc-_124\"",
            "\"\\999bc-_123\"",
            "\"\\09bc-_123\"",
            "\"abc-_123\\\"",
        ] {
            assert!(!txt_matches(value, "abc-_123"));
        }
        assert!(!txt_matches(&format!("\"{}\"", "a".repeat(513)), "a"));
    }
}
