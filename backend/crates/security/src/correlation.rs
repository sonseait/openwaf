//! Process-local client correlation; never an authentication or enforcement signal.
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
pub const COOKIE: &str = "__Host-openwaf-client";
pub struct Correlator {
    key: PKey<openssl::pkey::Private>,
}
impl Correlator {
    pub fn new() -> anyhow::Result<Self> {
        let mut secret = zeroize::Zeroizing::new([0; 32]);
        openssl::rand::rand_bytes(secret.as_mut())?;
        Ok(Self {
            key: PKey::hmac(secret.as_ref())?,
        })
    }
    fn digest(&self, fields: &[&[u8]]) -> Option<String> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).ok()?;
        for field in fields {
            signer.update(&(field.len() as u64).to_be_bytes()).ok()?;
            signer.update(field).ok()?;
        }
        Some(
            signer
                .sign_to_vec()
                .ok()?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
    pub fn verified(&self, route: &str, namespace: &str, value: &[u8]) -> Option<String> {
        if value.is_empty() || value.len() > 1024 {
            return None;
        }
        self.digest(&[b"verified", route.as_bytes(), namespace.as_bytes(), value])
    }
    pub fn issue(&self, host: &str, now: u64) -> Option<String> {
        let mut nonce = [0; 16];
        openssl::rand::rand_bytes(&mut nonce).ok()?;
        let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let body = format!("{now}.{nonce}");
        Some(format!(
            "{body}.{}",
            self.digest(&[b"cookie", host.as_bytes(), body.as_bytes()])?
        ))
    }
    pub fn cookie(&self, host: &str, token: &str, now: u64) -> Option<String> {
        if token.len() > 128 {
            return None;
        }
        let (body, signature) = token.rsplit_once('.')?;
        let (issued, nonce) = body.split_once('.')?;
        let issued: u64 = issued.parse().ok()?;
        if issued > now
            || now - issued > 1800
            || nonce.len() != 32
            || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let expected = self.digest(&[b"cookie", host.as_bytes(), body.as_bytes()])?;
        if signature.len() != expected.len()
            || !openssl::memcmp::eq(expected.as_bytes(), signature.as_bytes())
        {
            return None;
        }
        self.digest(&[b"session", host.as_bytes(), nonce.as_bytes()])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_cookie_is_host_bound_expires_and_rejects_tampering() {
        let service = Correlator::new().unwrap();
        let token = service.issue("app.test", 100).unwrap();
        assert!(service.cookie("app.test", &token, 101).is_some());
        assert!(service.cookie("other.test", &token, 101).is_none());
        assert!(service.cookie("app.test", &token, 100 + 1801).is_none());
        assert!(
            service
                .cookie("app.test", &(token.clone() + "0"), 101)
                .is_none()
        );
        assert!(
            Correlator::new()
                .unwrap()
                .cookie("app.test", &token, 101)
                .is_none()
        );
    }
    #[test]
    fn identity_is_namespaced_and_no_raw_value_is_retained() {
        let service = Correlator::new().unwrap();
        let a = service
            .verified("app", "auth:/verify:user", b"private-user")
            .unwrap();
        assert_eq!(
            a,
            service
                .verified("app", "auth:/verify:user", b"private-user")
                .unwrap()
        );
        assert_ne!(
            a,
            service
                .verified("other", "auth:/verify:user", b"private-user")
                .unwrap()
        );
        assert!(!a.contains("private-user"));
        assert!(service.verified("app", "auth", b"").is_none());
    }
}
