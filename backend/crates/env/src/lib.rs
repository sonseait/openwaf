//! Local startup configuration, loaded before any application threads exist.
#![forbid(unsafe_code)]
use anyhow::{Result, bail, ensure};
use std::{env, fs::File, io::Read, path::PathBuf};

const LIMIT: u64 = 64 * 1024;

/// Call once from synchronous main, before constructing Tokio/native workers.
/// Existing environment wins. Only the current directory is searched; an explicit
/// OPENWAF_ENV_FILE is required to load elsewhere. /dev/null disables loading.
/// Never return dotenvy's errors: parser errors may contain credential values.
pub fn load() -> Result<()> {
    let explicit = env::var_os("OPENWAF_ENV_FILE");
    let path = explicit
        .as_ref()
        .map_or_else(|| PathBuf::from(".env"), PathBuf::from);
    if path == std::path::Path::new("/dev/null") {
        return Ok(());
    }
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(_) => bail!("cannot read startup .env file"),
    };
    ensure!(
        metadata.is_file() && metadata.len() <= LIMIT,
        "startup .env must be a regular file of at most 64 KiB"
    );
    let mut data = Vec::new();
    File::open(path)
        .and_then(|file| file.take(LIMIT + 1).read_to_end(&mut data))
        .map_err(|_| anyhow::anyhow!("cannot read startup .env file"))?;
    ensure!(data.len() as u64 <= LIMIT, "startup .env exceeds 64 KiB");
    dotenvy::from_read(data.as_slice()).map_err(|_| anyhow::anyhow!("invalid startup .env syntax"))
}
