//! Admin secret domain: authenticated name binding, versioned AES-256-GCM.
use anyhow::{Context, Result, ensure};
use openssl::{hash::MessageDigest, pkey::PKey, rand::rand_bytes, sign::Signer, symm};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct MasterKey(Zeroizing<Vec<u8>>);

pub fn private_file(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open private admin input")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= max as u64,
        "admin secret input must be an owner-only bounded regular file"
    );
    let mut data = Zeroizing::new(Vec::new());
    file.take((max + 1) as u64).read_to_end(&mut data)?;
    ensure!(data.len() <= max, "admin secret input too large");
    Ok(data)
}

impl MasterKey {
    pub fn load(path: &Path) -> Result<Self> {
        let data = private_file(path, 32)?;
        ensure!(
            data.len() == 32,
            "admin master key must contain 32 raw bytes"
        );
        Ok(Self(data))
    }
    pub fn seal(&self, name: &str, plain: &[u8]) -> Result<Vec<u8>> {
        ensure!(plain.len() <= 2048, "credential too large");
        let mut nonce = [0; 12];
        let mut tag = [0; 16];
        rand_bytes(&mut nonce)?;
        let aad = format!("openwaf-admin-secret-v1:{name}");
        let encrypted = symm::encrypt_aead(
            symm::Cipher::aes_256_gcm(),
            &self.0,
            Some(&nonce),
            aad.as_bytes(),
            plain,
            &mut tag,
        )?;
        Ok([b"OWAD1".as_slice(), &nonce, &tag, &encrypted].concat())
    }
    pub fn open(&self, name: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            (33..=2081).contains(&data.len()) && &data[..5] == b"OWAD1",
            "invalid admin credential envelope"
        );
        let aad = format!("openwaf-admin-secret-v1:{name}");
        let plain = symm::decrypt_aead(
            symm::Cipher::aes_256_gcm(),
            &self.0,
            Some(&data[5..17]),
            aad.as_bytes(),
            &data[33..],
            &data[17..33],
        )
        .map_err(|_| anyhow::anyhow!("admin master key or credential integrity check failed"))?;
        Ok(Zeroizing::new(plain))
    }
    pub fn csrf(&self, token: &str) -> Result<String> {
        let key = PKey::hmac(&self.0)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(b"openwaf-admin-csrf-v1:")?;
        signer.update(token.as_bytes())?;
        Ok(hex(&signer.sign_to_vec()?))
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn random_token() -> Result<String> {
    let mut bytes = [0; 32];
    rand_bytes(&mut bytes)?;
    Ok(hex(&bytes))
}
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_binds_name_key_version_and_integrity() -> Result<()> {
        let key = MasterKey(Zeroizing::new(vec![7; 32]));
        let other = MasterKey(Zeroizing::new(vec![8; 32]));
        let mut sealed = key.seal("test", b"example")?;
        assert_eq!(key.open("test", &sealed)?.as_slice(), b"example");
        assert!(key.open("different", &sealed).is_err());
        assert!(other.open("test", &sealed).is_err());
        sealed[20] ^= 1;
        assert!(key.open("test", &sealed).is_err());
        assert!(key.open("test", b"OWAD2").is_err());
        assert_ne!(key.csrf("one")?, key.csrf("two")?);
        Ok(())
    }
    #[test]
    fn rejects_public_symlink_and_oversize_key() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("key");
        std::fs::write(&path, [0; 32])?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(MasterKey::load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(MasterKey::load(&path).is_ok());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(MasterKey::load(&link).is_err());
        std::fs::write(&path, [0; 33])?;
        assert!(MasterKey::load(&path).is_err());
        Ok(())
    }
}
