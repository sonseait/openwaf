//! Cookie values contain a logical endpoint digest, expiry and HMAC, no client
//! identity or native connection address. Only prepared in-memory key material.
use anyhow::{Context, Result, ensure};
use openssl::{
    hash::{MessageDigest, hash},
    pkey::PKey,
    sign::Signer,
};
use openwaf_config::{Endpoint, operations::Operations};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
pub struct SignerKey(PKey<openssl::pkey::Private>);
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> Result<String> {
    Ok(hex(&hash(MessageDigest::sha256(), bytes)?))
}
impl SignerKey {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut bytes = [0; 32];
        if let Some(path) = path {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .context("open affinity key")?;
            let meta = file.metadata()?;
            ensure!(
                meta.is_file() && meta.len() == 32 && meta.permissions().mode() & 0o077 == 0,
                "affinity key must be 32 bytes in owner-only regular file"
            );
            file.read_exact(&mut bytes)?;
        } else {
            openssl::rand::rand_bytes(&mut bytes)?;
        }
        let key = PKey::hmac(&bytes)?;
        bytes.fill(0);
        Ok(Self(key))
    }
    pub fn name(upstream: &str) -> Result<String> {
        Ok(format!(
            "__Host-openwaf-{}",
            &digest(upstream.as_bytes())?[..16]
        ))
    }
    pub fn endpoint(upstream: &str, endpoint: &Endpoint) -> Result<String> {
        digest(Operations::key(upstream, endpoint).as_bytes())
    }
    fn mac(&self, host: &str, upstream: &str, value: &str) -> Result<String> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.0)?;
        for part in ["openwaf-affinity-v1", host, upstream, value] {
            signer.update(part.as_bytes())?;
            signer.update(&[0])?;
        }
        Ok(hex(&signer.sign_to_vec()?))
    }
    pub fn issue(
        &self,
        host: &str,
        upstream: &str,
        endpoint: &Endpoint,
        lifetime: u32,
        now: u64,
    ) -> Result<String> {
        let value = format!(
            "{}.{}",
            Self::endpoint(upstream, endpoint)?,
            now.saturating_add(u64::from(lifetime) * 1000)
        );
        Ok(format!(
            "{}={}.{}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            Self::name(upstream)?,
            value,
            self.mac(host, upstream, &value)?,
            lifetime
        ))
    }
    pub fn verify(
        &self,
        host: &str,
        upstream: &str,
        value: &str,
        lifetime: u32,
        now: u64,
    ) -> Option<String> {
        if value.len() > 160 {
            return None;
        }
        let (body, mac) = value.rsplit_once('.')?;
        let (endpoint, expiry) = body.split_once('.')?;
        let expiry: u64 = expiry.parse().ok()?;
        if endpoint.len() != 64
            || !endpoint.bytes().all(|b| b.is_ascii_hexdigit())
            || expiry <= now
            || expiry > now.saturating_add(u64::from(lifetime) * 1000)
        {
            return None;
        }
        let expected = self.mac(host, upstream, body).ok()?;
        if mac.len() != expected.len() || !openssl::memcmp::eq(mac.as_bytes(), expected.as_bytes())
        {
            return None;
        }
        Some(endpoint.to_owned())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_cookie_scope_tamper_expiry_restart_and_logical_identity() {
        let key = SignerKey::load(None).unwrap();
        let endpoint: Endpoint = serde_json::from_value(
            serde_json::json!({"address":"service.test:8080","protocol":"http"}),
        )
        .unwrap();
        let cookie = key.issue("app.test", "pool", &endpoint, 60, 1000).unwrap();
        let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
        assert!(key.verify("app.test", "pool", value, 60, 1000).is_some());
        assert!(key.verify("other.test", "pool", value, 60, 1000).is_none());
        assert!(key.verify("app.test", "other", value, 60, 1000).is_none());
        assert!(key.verify("app.test", "pool", value, 60, 61000).is_none());
        assert!(
            SignerKey::load(None)
                .unwrap()
                .verify("app.test", "pool", value, 60, 1000)
                .is_none()
        );
        assert!(
            key.verify("app.test", "pool", &format!("{value}0"), 60, 1000)
                .is_none()
        );
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Lax"));
    }
}
