//! Immutable static artifacts. All ZIP/filesystem preparation runs outside proxy executors.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use cap_std::{ambient_authority, fs::Dir};
use openwaf_config::{
    Snapshot,
    application::{Mode, Target, valid_id},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub struct Capacity;
impl std::fmt::Display for Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("applications storage quota exceeded")
    }
}
impl std::error::Error for Capacity {}

#[derive(Clone, Copy, Serialize)]
pub struct Limits {
    pub zip_bytes: u64,
    pub expanded_bytes: u64,
    pub files: usize,
    pub total_bytes: u64,
    pub retained_releases: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            zip_bytes: 100 * 1024 * 1024,
            expanded_bytes: 500 * 1024 * 1024,
            files: 10_000,
            total_bytes: 5 * 1024 * 1024 * 1024,
            retained_releases: 5,
        }
    }
}
impl Limits {
    pub fn from_env() -> Result<Self> {
        let mut value = Self::default();
        for (name, field) in [
            ("OPENWAF_APPLICATIONS_ZIP_BYTES", &mut value.zip_bytes),
            (
                "OPENWAF_APPLICATIONS_EXPANDED_BYTES",
                &mut value.expanded_bytes,
            ),
            ("OPENWAF_APPLICATIONS_TOTAL_BYTES", &mut value.total_bytes),
        ] {
            if let Some(raw) = std::env::var_os(name) {
                *field = raw
                    .to_str()
                    .context("invalid applications limit")?
                    .parse()
                    .context("invalid applications limit")?;
            }
        }
        ensure!(
            value.zip_bytes > 0
                && value.zip_bytes <= 1024 * 1024 * 1024
                && value.expanded_bytes > 0
                && value.expanded_bytes <= 4 * 1024 * 1024 * 1024
                && value.total_bytes >= value.zip_bytes.saturating_add(value.expanded_bytes),
            "invalid applications capacity limits"
        );
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub bytes: u64,
    pub etag: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub application_id: String,
    pub release_id: String,
    pub checksum: String,
    pub bytes: u64,
    pub files: BTreeMap<String, Entry>,
}
pub struct Release {
    pub manifest: Manifest,
    dir: Dir,
}
pub struct Prepared {
    pub store: Arc<Store>,
    pub routes: Vec<Option<Arc<Release>>>,
}
pub struct Store {
    root: PathBuf,
    pub limits: Limits,
    registry: Mutex<BTreeMap<String, Arc<Release>>>,
    pub writer: Arc<tokio::sync::Mutex<()>>,
    io: Arc<Semaphore>,
}
pub fn id() -> Result<String> {
    let mut bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(hex(&bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
impl Store {
    pub fn open(root: PathBuf, limits: Limits) -> Result<Arc<Self>> {
        ensure!(root.is_absolute(), "applications root must be absolute");
        for directory in ["releases", "staging"] {
            std::fs::create_dir_all(root.join(directory)).map_err(|error| {
                anyhow::anyhow!(
                    "Applications storage initialization failed: OPENWAF_APPLICATIONS_ROOT must point to a writable container mount owned by the gateway user: {error}"
                )
            })?;
        }
        let root = root.canonicalize()?;
        Ok(Arc::new(Self {
            root,
            limits,
            registry: Mutex::new(BTreeMap::new()),
            writer: Arc::new(tokio::sync::Mutex::new(())),
            io: Arc::new(Semaphore::new(64)),
        }))
    }
    pub fn reserve_upload(&self) -> Result<()> {
        ensure!(
            disk_bytes(&self.root)?
                <= self
                    .limits
                    .total_bytes
                    .saturating_sub(self.limits.zip_bytes)
                    .saturating_sub(self.limits.expanded_bytes)
                    .saturating_sub(4 * 1024 * 1024)
                    .saturating_sub(self.limits.files as u64 * 8192),
            Capacity
        );
        Ok(())
    }
    pub fn staging(&self, name: &str) -> Result<PathBuf> {
        ensure!(valid_id(name), "invalid staging id");
        Ok(self.root.join("staging").join(format!("{name}.zip")))
    }
    pub async fn prepare(self: &Arc<Self>, mut snapshot: Snapshot) -> Result<Snapshot> {
        let store = self.clone();
        let _permit = self
            .io
            .clone()
            .try_acquire_owned()
            .context("application preparation capacity")?;
        tokio::task::spawn_blocking(move || {
            let _permit = _permit;
            let mut routes = Vec::with_capacity(snapshot.document.routes.len());
            for route in &snapshot.document.routes {
                routes.push(
                    route
                        .application
                        .as_ref()
                        .map(|target| store.load(target))
                        .transpose()?,
                );
            }
            snapshot.applications = Some(Arc::new(Prepared { store, routes }));
            Ok(snapshot)
        })
        .await
        .context("application preparation worker failed")?
    }
    fn load(&self, target: &Target) -> Result<Arc<Release>> {
        target.validate()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact registry unavailable"))?;
        if let Some(release) = registry.get(&target.release_id) {
            ensure!(
                release.manifest.application_id == target.application_id,
                "application ownership mismatch"
            );
            return Ok(release.clone());
        }
        // Only a bounded metadata file is read here; no ZIP parsing on requests.
        let base = self.root.join("releases").join(&target.release_id);
        let mut bytes = Vec::new();
        std::fs::File::open(base.join("manifest.json"))?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4 * 1024 * 1024, "artifact manifest limit");
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        ensure!(
            manifest.schema_version == 1
                && manifest.release_id == target.release_id
                && manifest.application_id == target.application_id
                && manifest.files.len() <= self.limits.files
                && manifest.files.contains_key("index.html"),
            "invalid artifact manifest"
        );
        let dir = Dir::open_ambient_dir(base.join("public"), ambient_authority())?;
        for (name, entry) in &manifest.files {
            ensure!(
                safe_name(name)
                    && entry.etag.len() == 66
                    && entry.etag.starts_with('"')
                    && entry.etag.ends_with('"')
                    && entry.etag[1..65].bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid artifact entry"
            );
            let meta = dir.symlink_metadata(name)?;
            ensure!(
                meta.is_file() && meta.len() == entry.bytes,
                "artifact file unavailable"
            );
        }
        // Evict unleased registry entries; snapshots retain the actual release objects.
        registry.retain(|_, release| Arc::strong_count(release) > 1);
        ensure!(registry.len() < 640, "artifact registry capacity");
        let release = Arc::new(Release { manifest, dir });
        registry.insert(target.release_id.clone(), release.clone());
        Ok(release)
    }
    /// Caller holds writer through this worker (including cancellation).
    pub fn ingest(&self, app: &str, release: &str, source: &Path) -> Result<Manifest> {
        ensure!(valid_id(app) && valid_id(release), "invalid artifact id");
        let limits = self.limits;
        ensure!(
            disk_bytes(&self.root)? <= limits.total_bytes.saturating_sub(limits.expanded_bytes),
            Capacity
        );
        let temporary = self.root.join("staging").join(release);
        std::fs::create_dir(&temporary)?;
        let outcome = self.extract(app, release, source, &temporary);
        if outcome.is_err() {
            std::fs::remove_dir_all(&temporary).context("cannot clean rejected artifact")?;
        }
        outcome
    }
    fn extract(
        &self,
        app: &str,
        release: &str,
        source: &Path,
        temporary: &Path,
    ) -> Result<Manifest> {
        let limits = self.limits;
        let deadline = Instant::now() + Duration::from_secs(60);
        let input = std::fs::File::open(source)?;
        ensure!(input.metadata()?.len() <= limits.zip_bytes, "ZIP too large");
        let mut hasher = openssl::sha::Sha256::new();
        let mut reader = input.try_clone()?;
        let mut buffer = [0u8; 65536];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        use std::io::{Seek, SeekFrom};
        let mut input = input;
        input.seek(SeekFrom::Start(0))?;
        let checksum = hex(&hasher.finish());
        let entries = preflight_zip(&mut input, limits.files * 2)?;
        input.seek(SeekFrom::Start(0))?;
        let mut archive = zip::ZipArchive::new(input).context("invalid ZIP")?;
        ensure!(
            archive.len() == entries,
            "ZIP entries were deduplicated or renamed"
        );
        ensure!(
            !archive.is_empty() && archive.len() <= limits.files * 2,
            "ZIP entry limit"
        );
        let mut names = Vec::new();
        let mut declared = 0u64;
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .context("unsupported or encrypted ZIP entry")?;
            let name = entry.name().trim_end_matches('/');
            ensure!(
                safe_name(name) && seen.insert(name.to_owned()),
                "unsafe or duplicate ZIP path"
            );
            let kind = entry.unix_mode().unwrap_or(0) & 0o170000;
            ensure!(
                kind == 0 || kind == 0o100000 || (entry.is_dir() && kind == 0o040000),
                "ZIP links and special files are forbidden"
            );
            if !entry.is_dir() {
                names.push((i, name.to_owned()));
                declared = declared
                    .checked_add(entry.size())
                    .context("ZIP size overflow")?;
            }
        }
        ensure!(
            names.len() <= limits.files && declared <= limits.expanded_bytes,
            "expanded ZIP limit"
        );
        let prefix = if names.iter().any(|(_, n)| n == "index.html") {
            String::new()
        } else {
            let first = names
                .first()
                .and_then(|(_, n)| n.split_once('/'))
                .map(|(p, _)| format!("{p}/"))
                .context("missing index.html")?;
            ensure!(
                names.iter().all(|(_, n)| n.starts_with(&first))
                    && names
                        .iter()
                        .any(|(_, n)| n == &format!("{first}index.html")),
                "ZIP must contain one build root with index.html"
            );
            first
        };
        let public = temporary.join("public");
        std::fs::create_dir(&public)?;
        let mut files = BTreeMap::new();
        let mut directories = std::collections::BTreeSet::new();
        let mut bytes = 0u64;
        for (i, name) in names {
            ensure!(Instant::now() < deadline, "artifact extraction deadline");
            let name = name.strip_prefix(&prefix).context("invalid ZIP root")?;
            ensure!(safe_name(name), "invalid normalized ZIP path");
            let mut parent = Path::new(name).parent();
            while let Some(path) = parent.filter(|p| !p.as_os_str().is_empty()) {
                directories.insert(path.to_owned());
                ensure!(
                    directories.len() <= limits.files,
                    "expanded directory limit"
                );
                parent = path.parent();
            }
            let output = public.join(name);
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            let mut input = archive.by_index(i)?;
            let mut hash = openssl::sha::Sha256::new();
            let mut count = 0u64;
            loop {
                ensure!(Instant::now() < deadline, "artifact extraction deadline");
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                count += n as u64;
                bytes = bytes.checked_add(n as u64).context("ZIP overflow")?;
                ensure!(bytes <= limits.expanded_bytes, "expanded ZIP limit");
                output.write_all(&buffer[..n])?;
                hash.update(&buffer[..n]);
            }
            output.sync_all()?;
            files.insert(
                name.to_owned(),
                Entry {
                    bytes: count,
                    etag: format!("\"{}\"", hex(&hash.finish())),
                },
            );
        }
        let manifest = Manifest {
            schema_version: 1,
            application_id: app.to_owned(),
            release_id: release.to_owned(),
            checksum,
            bytes,
            files,
        };
        let mut output = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temporary.join("manifest.json"))?;
        let encoded = serde_json::to_vec(&manifest)?;
        ensure!(
            encoded.len() <= 4 * 1024 * 1024,
            "artifact manifest capacity"
        );
        output.write_all(&encoded)?;
        output.sync_all()?;
        sync_dirs(&public)?;
        std::fs::File::open(temporary)?.sync_all()?;
        ensure!(disk_bytes(&self.root)? <= limits.total_bytes, Capacity);
        std::fs::rename(temporary, self.root.join("releases").join(release))?;
        std::fs::File::open(self.root.join("releases"))?.sync_all()?;
        Ok(manifest)
    }
    pub fn remove(&self, release: &str) -> Result<bool> {
        ensure!(valid_id(release), "invalid release id");
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| anyhow::anyhow!("artifact registry unavailable"))?;
        if registry
            .get(release)
            .is_some_and(|r| Arc::strong_count(r) > 1)
        {
            return Ok(false);
        }
        registry.remove(release);
        let path = self.root.join("releases").join(release);
        if path.try_exists()? {
            std::fs::remove_dir_all(path)?;
            std::fs::File::open(self.root.join("releases"))?.sync_all()?;
        }
        Ok(true)
    }
    pub fn sweep(&self, known: &std::collections::BTreeSet<String>) -> Result<()> {
        let cutoff = SystemTime::now() - Duration::from_secs(3600);
        for entry in std::fs::read_dir(self.root.join("staging"))? {
            let entry = entry?;
            if entry.metadata()?.modified()? < cutoff {
                if entry.file_type()?.is_dir() {
                    std::fs::remove_dir_all(entry.path())?;
                } else {
                    std::fs::remove_file(entry.path())?;
                }
            }
        }
        for entry in std::fs::read_dir(self.root.join("releases"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if valid_id(&name) && !known.contains(&name) {
                self.remove(&name)?;
            }
        }
        Ok(())
    }
    pub async fn response(
        self: &Arc<Self>,
        release: Arc<Release>,
        mode: Mode,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
    ) -> Result<Reply> {
        let permit = Arc::new(
            self.io
                .clone()
                .try_acquire_owned()
                .context("static file capacity")?,
        );
        let requested = request_path(path)?;
        let navigation = headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|v| v.trim().split(';').next() == Some("text/html"))
            })
            && headers
                .get("sec-fetch-dest")
                .is_none_or(|v| v == "document" || v == "iframe" || v == "empty");
        let name = if release.manifest.files.contains_key(&requested) {
            requested
        } else {
            let index = if requested.is_empty() {
                "index.html".to_owned()
            } else {
                format!("{}/index.html", requested.trim_end_matches('/'))
            };
            if release.manifest.files.contains_key(&index) {
                if !requested.is_empty() && !path.ends_with('/') {
                    let mut reply = Reply::empty(308, permit);
                    reply.headers.push(("location", format!("{path}/")));
                    return Ok(reply);
                }
                index
            } else if mode == Mode::Spa
                && navigation
                && !requested.rsplit('/').next().unwrap_or("").contains('.')
            {
                "index.html".to_owned()
            } else {
                return Ok(Reply::empty(404, permit));
            }
        };
        let entry = release
            .manifest
            .files
            .get(&name)
            .context("missing artifact entry")?;
        let etag = entry.etag.clone();
        let bytes = entry.bytes;
        let mime = mime_guess::from_path(&name)
            .first_or_octet_stream()
            .to_string();
        let mut reply = Reply {
            status: 200,
            headers: vec![
                ("content-type", mime),
                ("etag", etag.clone()),
                ("accept-ranges", "bytes".into()),
                ("cache-control", "no-cache".into()),
                ("x-content-type-options", "nosniff".into()),
            ],
            file: None,
            offset: 0,
            length: bytes,
            _permit: permit,
            _release: Some(release.clone()),
        };
        if headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|t| t.trim() == etag || t.trim() == format!("W/{etag}") || t.trim() == "*")
            })
        {
            reply.status = 304;
            reply.length = 0;
            return Ok(reply);
        }
        if let Some(range) = headers
            .get("range")
            .and_then(|v| v.to_str().ok())
            .filter(|_| headers.get("if-range").is_none_or(|v| v == etag.as_str()))
        {
            match byte_range(range, bytes) {
                Some((start, end)) => {
                    reply.status = 206;
                    reply.offset = start;
                    reply.length = end - start + 1;
                    reply
                        .headers
                        .push(("content-range", format!("bytes {start}-{end}/{bytes}")));
                }
                None => {
                    reply.status = 416;
                    reply.length = 0;
                    reply
                        .headers
                        .push(("content-range", format!("bytes */{bytes}")));
                    return Ok(reply);
                }
            }
        }
        if method != "HEAD" && reply.length > 0 {
            // The worker owns the I/O permit and release lease even if its caller
            // is cancelled while the filesystem open is still in progress.
            return tokio::task::spawn_blocking(move || -> Result<Reply> {
                let opened = release.dir.open(name)?.into_std();
                reply.file = Some(ArtifactFile {
                    inner: Some(opened),
                    permit: reply._permit.clone(),
                    release,
                });
                Ok(reply)
            })
            .await?;
        }
        Ok(reply)
    }
}
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub file: Option<ArtifactFile>,
    pub offset: u64,
    pub length: u64,
    _permit: Arc<OwnedSemaphorePermit>,
    _release: Option<Arc<Release>>,
}
impl Reply {
    fn empty(status: u16, permit: Arc<OwnedSemaphorePermit>) -> Self {
        Self {
            status,
            headers: vec![],
            file: None,
            offset: 0,
            length: 0,
            _permit: permit,
            _release: None,
        }
    }
}
pub struct ArtifactFile {
    inner: Option<std::fs::File>,
    permit: Arc<OwnedSemaphorePermit>,
    release: Arc<Release>,
}
impl ArtifactFile {
    /// Cancellation cannot release capacity or reclaim a release while native
    /// filesystem I/O is still running. Only one bounded chunk is in flight.
    pub async fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        ensure!(length <= 65536, "artifact read chunk limit");
        let mut file = self
            .inner
            .take()
            .context("artifact read already in flight")?;
        let permit = self.permit.clone();
        let release = self.release.clone();
        let (file, result) = tokio::task::spawn_blocking(move || {
            use std::io::{Seek, SeekFrom};
            let (_permit, _release) = (permit, release);
            let result = (|| -> Result<Vec<u8>> {
                file.seek(SeekFrom::Start(offset))?;
                let mut bytes = vec![0; length];
                let count = file.read(&mut bytes)?;
                bytes.truncate(count);
                Ok(bytes)
            })();
            (file, result)
        })
        .await?;
        self.inner = Some(file);
        result
    }
}
// Inspect the raw central directory before the ZIP library builds its filename map.
// Small frontend artifacts do not need ZIP64 or split archives. Rejecting those also
// bounds allocation before parsing and makes duplicate filenames observable.
fn preflight_zip(input: &mut std::fs::File, max_entries: usize) -> Result<usize> {
    use std::io::{Seek, SeekFrom};
    let length = input.metadata()?.len();
    let tail_length = length.min(65557) as usize;
    input.seek(SeekFrom::End(-(tail_length as i64)))?;
    let mut tail = vec![0u8; tail_length];
    input.read_exact(&mut tail)?;
    let u16_at = |bytes: &[u8], offset: usize| {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize
    };
    let u32_at = |bytes: &[u8], offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as u64
    };
    let end = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|offset| {
            tail[*offset..].starts_with(b"PK\x05\x06")
                && *offset + 22 + u16_at(&tail, *offset + 20) == tail.len()
        })
        .context("invalid ZIP end record")?;
    let end = &tail[end..];
    let count = u16_at(end, 10);
    let size = u32_at(end, 12);
    let offset = u32_at(end, 16);
    ensure!(
        u16_at(end, 4) == 0
            && u16_at(end, 6) == 0
            && u16_at(end, 8) == count
            && count > 0
            && count <= max_entries
            && size <= 32 * 1024 * 1024
            && offset + size <= length
            && offset != u32::MAX as u64,
        "ZIP64, split archives or excessive central directory are unsupported"
    );
    input.seek(SeekFrom::Start(offset))?;
    let mut names = std::collections::BTreeSet::new();
    for _ in 0..count {
        let mut header = [0u8; 46];
        input.read_exact(&mut header)?;
        ensure!(
            header.starts_with(b"PK\x01\x02") && u16_at(&header, 8) & 1 == 0,
            "invalid or encrypted ZIP header"
        );
        let name_length = u16_at(&header, 28);
        let extra = u16_at(&header, 30);
        let comment = u16_at(&header, 32);
        ensure!(name_length <= 1025, "ZIP filename limit");
        let mut name = vec![0u8; name_length];
        input.read_exact(&mut name)?;
        let name = std::str::from_utf8(&name)?.trim_end_matches('/');
        ensure!(
            safe_name(name) && names.insert(name.to_owned()),
            "unsafe or duplicate ZIP filename"
        );
        input.seek(SeekFrom::Current((extra + comment) as i64))?;
        ensure!(
            input.stream_position()? <= offset + size,
            "invalid central directory length"
        );
    }
    ensure!(
        input.stream_position()? == offset + size,
        "central directory count mismatch"
    );
    Ok(count)
}
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.contains('\\')
        && !name.contains(':')
        && !name.chars().any(char::is_control)
        && name
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && s.len() <= 255)
}
pub fn request_path(path: &str) -> Result<String> {
    let mut decoded = Vec::new();
    let mut source = path.as_bytes().iter().copied();
    while let Some(b) = source.next() {
        if b == b'%' {
            let a = source.next().context("invalid escape")?;
            let b = source.next().context("invalid escape")?;
            let s = [a, b];
            decoded.push(u8::from_str_radix(std::str::from_utf8(&s)?, 16)?);
        } else {
            decoded.push(b);
        }
    }
    let path = String::from_utf8(decoded)?;
    let relative = path
        .strip_prefix('/')
        .context("absolute request path required")?
        .trim_end_matches('/');
    ensure!(
        relative.is_empty() || safe_name(relative),
        "unsafe request path"
    );
    Ok(relative.to_owned())
}
fn byte_range(value: &str, length: u64) -> Option<(u64, u64)> {
    if length == 0 {
        return None;
    }
    let (a, b) = value.strip_prefix("bytes=")?.split_once('-')?;
    if a.is_empty() {
        let suffix = b.parse::<u64>().ok()?;
        return (suffix > 0).then_some((length.saturating_sub(suffix), length - 1));
    }
    let start = a.parse::<u64>().ok()?;
    let end = if b.is_empty() {
        length - 1
    } else {
        b.parse::<u64>().ok()?.min(length - 1)
    };
    (start < length && end >= start).then_some((start, end))
}
fn sync_dirs(path: &Path) -> Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_dirs(&entry.path())?;
        }
    }
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn disk_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    fn visit(path: &Path, count: &mut usize) -> Result<u64> {
        let mut bytes = 0u64;
        for entry in std::fs::read_dir(path)? {
            *count += 1;
            ensure!(*count <= 1_000_000, "artifact inventory capacity");
            let entry = entry?;
            let meta = entry.metadata()?;
            ensure!(
                !entry.file_type()?.is_symlink(),
                "unexpected artifact symlink"
            );
            let child = if meta.is_dir() {
                visit(&entry.path(), count)?
            } else {
                0
            };
            bytes = bytes
                .checked_add(meta.len().max(meta.blocks().saturating_mul(512)))
                .and_then(|bytes| bytes.checked_add(child))
                .context("artifact size overflow")?;
        }
        Ok(bytes)
    }
    visit(path, &mut 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openwaf_config::{Context, Document};
    use zip::write::SimpleFileOptions;
    fn fixture() -> (tempfile::TempDir, Arc<Store>) {
        let dir = tempfile::tempdir().expect("temp");
        let store = Store::open(dir.path().to_owned(), Limits::default()).expect("store");
        (dir, store)
    }
    fn archive(path: &Path, entries: &[(&str, &[u8])]) {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(path).expect("ZIP"));
        for (name, bytes) in entries {
            zip.start_file(
                *name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .expect("entry");
            zip.write_all(bytes).expect("content");
        }
        zip.finish().expect("finish");
    }
    fn target(app: &str, release: &str) -> Target {
        Target {
            application_id: app.into(),
            release_id: release.into(),
            mode: Mode::Spa,
            preview_expires_at_unix_ms: None,
        }
    }
    #[tokio::test]
    async fn immutable_releases_spa_assets_head_conditional_range_and_leases() {
        let (_dir, store) = fixture();
        let app = id().expect("id");
        let release = id().expect("id");
        let source = store.staging(&release).expect("path");
        archive(
            &source,
            &[
                ("dist/index.html", b"<h1>website</h1>"),
                ("dist/assets/app.js", b"javascript"),
                ("dist/docs/index.html", b"docs"),
            ],
        );
        let manifest = store.ingest(&app, &release, &source).expect("ingest");
        assert_eq!(manifest.files.len(), 3);
        assert!(manifest.files.contains_key("index.html"));
        let artifact = store.load(&target(&app, &release)).expect("load");
        let mut headers = http::HeaderMap::new();
        headers.insert("accept", http::HeaderValue::from_static("text/html"));
        let mut reply = store
            .response(
                artifact.clone(),
                Mode::Spa,
                "/settings/profile",
                "GET",
                &headers,
            )
            .await
            .expect("SPA");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.length, 16);
        assert_eq!(
            reply
                .file
                .as_mut()
                .expect("file")
                .read_at(0, 65536)
                .await
                .expect("read"),
            b"<h1>website</h1>"
        );
        let missing = store
            .response(
                artifact.clone(),
                Mode::Spa,
                "/assets/missing.js",
                "GET",
                &headers,
            )
            .await
            .expect("missing");
        assert_eq!(missing.status, 404);
        assert_eq!(
            store
                .response(artifact.clone(), Mode::Static, "/missing", "GET", &headers)
                .await
                .expect("static")
                .status,
            404
        );
        assert_eq!(
            store
                .response(artifact.clone(), Mode::Static, "/docs/", "GET", &headers)
                .await
                .expect("index")
                .length,
            4
        );
        headers.insert("range", http::HeaderValue::from_static("bytes=2-5"));
        let mut range = store
            .response(
                artifact.clone(),
                Mode::Static,
                "/assets/app.js",
                "GET",
                &headers,
            )
            .await
            .expect("range");
        assert_eq!((range.status, range.offset, range.length), (206, 2, 4));
        assert_eq!(
            range
                .file
                .as_mut()
                .expect("range file")
                .read_at(2, 4)
                .await
                .expect("read range"),
            b"vasc"
        );
        headers.insert(
            "if-none-match",
            http::HeaderValue::from_str(&artifact.manifest.files["assets/app.js"].etag)
                .expect("etag"),
        );
        let unchanged = store
            .response(
                artifact.clone(),
                Mode::Static,
                "/assets/app.js",
                "GET",
                &headers,
            )
            .await
            .expect("unchanged");
        assert_eq!(unchanged.status, 304);
        assert!(unchanged.file.is_none());
        let head = store
            .response(
                artifact.clone(),
                Mode::Static,
                "/assets/app.js",
                "HEAD",
                &http::HeaderMap::new(),
            )
            .await
            .expect("head");
        assert_eq!(head.length, 10);
        assert!(head.file.is_none());
        assert!(!store.remove(&release).expect("leased"));
        drop((reply, range, unchanged, head, artifact));
        assert!(store.remove(&release).expect("remove"));
        assert!(store.load(&target(&app, &release)).is_err());
    }
    #[test]
    fn rejects_traversal_duplicates_links_multiple_roots_and_expansion() {
        let (_dir, store) = fixture();
        let app = id().expect("id");
        for entries in [
            vec![("../index.html", b"bad".as_slice())],
            vec![("/index.html", b"bad".as_slice())],
            vec![
                ("a/index.html", b"a".as_slice()),
                ("b/file.js", b"b".as_slice()),
            ],
            vec![("a\\index.html", b"bad".as_slice())],
        ] {
            let release = id().expect("id");
            let source = store.staging(&release).expect("source");
            archive(&source, &entries);
            assert!(store.ingest(&app, &release, &source).is_err());
            assert!(!store.root.join("releases").join(&release).exists());
        }
        let duplicate = id().expect("id");
        let duplicate_path = store.staging(&duplicate).expect("source");
        archive(
            &duplicate_path,
            &[("index.html", b"a"), ("other.html", b"b")],
        );
        let encoded = std::fs::read(&duplicate_path).expect("read");
        let mut encoded = encoded;
        for offset in 0..encoded.len().saturating_sub(9) {
            if &encoded[offset..offset + 10] == b"other.html" {
                encoded[offset..offset + 10].copy_from_slice(b"index.html");
            }
        }
        std::fs::write(&duplicate_path, encoded).expect("write");
        assert!(store.ingest(&app, &duplicate, &duplicate_path).is_err());
        let release = id().expect("id");
        let source = store.staging(&release).expect("source");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&source).expect("ZIP"));
        zip.add_symlink("index.html", "/etc/passwd", SimpleFileOptions::default())
            .expect("link");
        zip.finish().expect("finish");
        assert!(store.ingest(&app, &release, &source).is_err());
        let small = Store::open(
            store.root.join("small"),
            Limits {
                expanded_bytes: 2,
                ..Limits::default()
            },
        )
        .expect("small");
        let release = id().expect("id");
        let source = small.staging(&release).expect("source");
        archive(&source, &[("index.html", b"huge")]);
        assert!(small.ingest(&app, &release, &source).is_err());
        let shallow = Store::open(
            store.root.join("shallow"),
            Limits {
                files: 2,
                ..Limits::default()
            },
        )
        .expect("shallow");
        let release = id().expect("id");
        let source = shallow.staging(&release).expect("source");
        archive(&source, &[("index.html", b"ok"), ("a/b/c/file.js", b"x")]);
        assert!(shallow.ingest(&app, &release, &source).is_err());
    }
    #[test]
    fn request_paths_and_ranges_never_escape_release() {
        for path in [
            "/../secret",
            "/%2e%2e/secret",
            "/%2fetc/passwd",
            "/%00",
            "/a\\b",
            "/a//b",
            "/%zz",
        ] {
            assert!(request_path(path).is_err(), "{path}");
        }
        assert_eq!(
            request_path("/assets/a%20b.js").expect("encoded"),
            "assets/a b.js"
        );
        assert_eq!(byte_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(byte_range("bytes=8-99", 10), Some((8, 9)));
        assert_eq!(byte_range("bytes=99-", 10), None);
        assert_eq!(byte_range("bytes=1-2,4-5", 10), None);
        assert_eq!(byte_range("bytes=-0", 10), None);
    }
    #[tokio::test]
    async fn preparation_pins_release_across_publication_and_restart() {
        let (dir, store) = fixture();
        let app = id().expect("id");
        let release = id().expect("id");
        let source = store.staging(&release).expect("source");
        archive(&source, &[("index.html", b"old release")]);
        store.ingest(&app, &release, &source).expect("ingest");
        let document:Document=serde_json::from_value(serde_json::json!({"routes":[{"id":"static","hostname":"app.test","path":"/","path_match":"prefix","application":target(&app,&release)}]})).expect("document");
        let context = Context {
            listeners: vec![],
            local_ips: vec![],
        };
        let snapshot = Snapshot::prepare(1, document.clone(), &context).expect("snapshot");
        let snapshot = store.prepare(snapshot).await.expect("prepared");
        assert!(!store.remove(&release).expect("snapshot lease"));
        let restarted = Store::open(dir.path().to_owned(), Limits::default()).expect("restart");
        restarted
            .prepare(Snapshot::prepare(2, document, &context).expect("snapshot"))
            .await
            .expect("restore");
        drop(snapshot);
        assert!(store.remove(&release).expect("retired"));
    }
}
