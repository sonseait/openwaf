//! Separate credential domain; no plaintext key in config or errors.
use anyhow::{Context, Result, ensure};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;
const AAD: &[u8] = b"openwaf-crowdsec-key-v1";
pub(crate) fn read(path: &Path, max: usize, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open security input")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= max as u64,
        "security input must be a bounded regular file"
    );
    ensure!(
        !private || meta.permissions().mode() & 0o077 == 0,
        "secret file must be owner-only"
    );
    let mut data = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut data)?;
    ensure!(data.len() <= max, "security input exceeds limit");
    Ok(data)
}
pub fn seal(input: &Path, output: &Path, master: &Path) -> Result<()> {
    let plaintext = Zeroizing::new(read(input, 1024, true)?);
    let key = Zeroizing::new(read(master, 32, true)?);
    ensure!(key.len() == 32, "master key must be 32 bytes");
    let mut nonce = [0; 12];
    rand_bytes(&mut nonce)?;
    let mut tag = [0; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        AAD,
        &plaintext,
        &mut tag,
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .context("create encrypted CrowdSec credential")?;
    for bytes in [b"OWCS1".as_slice(), &nonce, &tag, &ciphertext] {
        file.write_all(bytes)?;
    }
    file.sync_all()?;
    Ok(())
}
pub(crate) fn load(path: &Path, master: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let key = Zeroizing::new(read(master, 32, true)?);
    let data = read(path, 1100, true)?;
    ensure!(
        key.len() == 32 && data.len() >= 33 && &data[..5] == b"OWCS1",
        "invalid encrypted CrowdSec credential"
    );
    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&data[5..17]),
        AAD,
        &data[33..],
        &data[17..33],
    )
    .map_err(|_| anyhow::anyhow!("cannot decrypt CrowdSec credential"))?;
    Ok(Zeroizing::new(plain))
}
