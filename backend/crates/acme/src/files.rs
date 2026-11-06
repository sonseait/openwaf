//! Local control-plane storage, never used on the proxy/handshake hot path.
use anyhow::{Context, Result, ensure};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const AAD: &[u8] = b"openwaf-acme-account-v1";

#[derive(Clone, Copy)]
pub enum SecretKind {
    Account,
    CloudflareToken,
    DnsLease,
    AriReplacement,
}

impl SecretKind {
    fn domain(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::Account => (b"OWAC1", AAD),
            Self::CloudflareToken => (b"OWCF1", b"openwaf-cloudflare-token-v1"),
            Self::DnsLease => (b"OWDL1", b"openwaf-dns-lease-v1"),
            Self::AriReplacement => (b"OWAR1", b"openwaf-ari-replacement-v1"),
        }
    }
}

pub fn read(path: &Path, max: usize, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .context("cannot open ACME input")?;
    let metadata = file.metadata().context("cannot inspect ACME input")?;
    ensure!(
        metadata.is_file() && metadata.len() <= max as u64,
        "ACME input must be a bounded regular file"
    );
    ensure!(
        !private || metadata.permissions().mode() & 0o077 == 0,
        "secret file must be owner-only"
    );
    let mut bytes = Vec::new();
    file.take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .context("cannot read ACME input")?;
    ensure!(bytes.len() <= max, "ACME input exceeds limit");
    Ok(bytes)
}

pub fn directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        builder
            .mode(0o700)
            .create(path)
            .context("cannot create ACME directory")?;
    }
    let meta = fs::symlink_metadata(path).context("cannot inspect ACME directory")?;
    ensure!(
        meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
        "ACME directory must be an owner-only real directory"
    );
    Ok(())
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("cannot create immutable ACME output")?;
    file.write_all(bytes).context("cannot write ACME output")?;
    file.sync_all().context("cannot sync ACME output")
}

pub fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .context("cannot sync ACME directory")
}

pub fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    rand_bytes(&mut bytes).context("cannot obtain secure randomness")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

// Lock owner holds the file until all writes finish. A crash deliberately leaves
// a stale lock: the operator must verify no publisher is alive before removing it.
pub struct Lock(PathBuf);

impl Lock {
    pub fn acquire(path: PathBuf) -> Result<Self> {
        write_new(&path, b"openwaf-acme writer\n")
            .context("ACME writer lock exists or is unavailable")?;
        Ok(Self(path))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if fs::remove_file(&self.0).is_err() {
            eprintln!("ACME writer lock cleanup failed");
        }
    }
}

pub fn seal_kind(plaintext: &[u8], key: &[u8], kind: SecretKind) -> Result<Vec<u8>> {
    let (magic, aad) = kind.domain();
    ensure!(
        key.len() == 32,
        "master key must contain exactly 32 raw bytes"
    );
    let mut nonce = [0u8; 12];
    rand_bytes(&mut nonce).context("cannot obtain secure randomness")?;
    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        aad,
        plaintext,
        &mut tag,
    )
    .map_err(|_| anyhow::anyhow!("secret encryption failed"))?;
    Ok([magic, &nonce, &tag, &ciphertext].concat())
}

pub fn unseal_kind(envelope: &[u8], key: &[u8], kind: SecretKind) -> Result<Zeroizing<Vec<u8>>> {
    let (magic, aad) = kind.domain();
    ensure!(
        key.len() == 32 && envelope.len() >= 33 && &envelope[..5] == magic,
        "invalid encrypted secret envelope or master key"
    );
    decrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&envelope[5..17]),
        aad,
        &envelope[33..],
        &envelope[17..33],
    )
    .map(Zeroizing::new)
    .map_err(|_| anyhow::anyhow!("secret decryption/authentication failed"))
}

pub fn seal(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    seal_kind(plaintext, key, SecretKind::Account)
}
pub fn unseal(envelope: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    unseal_kind(envelope, key, SecretKind::Account)
}

/// Caller holds the state writer lock; same-directory rename is the commit.
pub fn replace_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("secret output requires parent directory")?;
    let temporary = parent.join(format!(".secret-{}", random_id()?));
    write_new(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        if fs::remove_file(&temporary).is_err() {
            eprintln!("secret temporary file cleanup failed");
        }
        return Err(error).context("cannot commit encrypted state");
    }
    sync_dir(parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_state_authentication_and_permissions() -> Result<()> {
        let key = [7; 32];
        let data = b"sensitive account credentials";
        let mut encrypted = seal(data, &key)?;
        assert!(!encrypted.windows(data.len()).any(|bytes| bytes == data));
        assert_eq!(&**unseal(&encrypted, &key)?, data);
        assert!(unseal(&encrypted, &[8; 32]).is_err());
        assert!(unseal_kind(&encrypted, &key, SecretKind::CloudflareToken).is_err());
        let token = seal_kind(data, &key, SecretKind::CloudflareToken)?;
        assert!(unseal(&token, &key).is_err());
        encrypted[33] ^= 1;
        assert!(unseal(&encrypted, &key).is_err());
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("state");
        write_new(&path, data)?;
        assert_eq!(read(&path, 128, true)?, data);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(read(&path, 128, true).is_err());
        assert!(read(&path, 1, false).is_err());
        Ok(())
    }
}
