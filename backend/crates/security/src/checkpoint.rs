//! Runtime recovery only. HMAC authenticates the bounded payload; atomic rename
//! and fsync keep the previous generation usable if a write fails. Dedicated sync
//! worker owns all disk I/O. No checkpoint path or contents enter request logs.
use super::*;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
const DOMAIN: &[u8] = b"openwaf-crowdsec-checkpoint-v1\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    mac: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u8,
    written_at_unix_ms: u64,
    boot_id: String,
    uptime_ms: u64,
    bans: Vec<Record>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: u64,
    network: String,
    expires_at_unix_ms: u64,
    remaining_ms: u64,
}
pub(super) struct Checkpoint {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    clock: fn() -> Result<(String, u64)>,
}
pub(super) fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn boot_clock() -> Result<(String, u64)> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(id.trim().len() == 36, "invalid boot identity");
    let uptime = std::fs::read_to_string("/proc/uptime")?;
    let seconds: f64 = uptime
        .split_whitespace()
        .next()
        .context("missing uptime")?
        .parse()?;
    ensure!(seconds.is_finite() && seconds >= 0.0, "invalid uptime");
    Ok((id.trim().to_owned(), (seconds * 1000.0) as u64))
}
impl Checkpoint {
    pub fn new(path: PathBuf, master: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("checkpoint requires private directory")?;
        let meta = std::fs::symlink_metadata(parent)?;
        ensure!(
            meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
            "checkpoint directory must be owner-only"
        );
        let key = Zeroizing::new(secret::read(master, 32, true)?);
        ensure!(key.len() == 32, "invalid checkpoint key");
        Ok(Self {
            path,
            key,
            clock: boot_clock,
        })
    }
    fn mac(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let key = PKey::hmac(&self.key)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(DOMAIN)?;
        signer.update(payload)?;
        Ok(signer.sign_to_vec()?)
    }
    pub fn load(&self) -> (Snapshot, &'static str) {
        let mut snapshot = Snapshot {
            wall_highwater: wall_ms(),
            bans: HashMap::new(),
            degraded: true,
            last_success: None,
        };
        if !self.path.exists() {
            return (snapshot, "missing");
        }
        let loaded = (|| -> Result<(HashMap<u64, Ban>, &'static str)> {
            let data = secret::read(&self.path, MAX_RESPONSE, true)?;
            let envelope: Envelope = serde_json::from_slice(&data)?;
            let mac = self.mac(envelope.payload.as_bytes())?;
            ensure!(
                envelope.mac.len() == mac.len() && openssl::memcmp::eq(&mac, &envelope.mac),
                "integrity"
            );
            let payload: Payload = serde_json::from_str(&envelope.payload)?;
            let (boot, uptime) = (self.clock)()?;
            snapshot.wall_highwater = snapshot.wall_highwater.max(payload.written_at_unix_ms);
            restore(payload, wall_ms(), Instant::now(), &boot, uptime)
        })();
        match loaded {
            Ok((bans, state)) => {
                snapshot.bans = bans;
                (snapshot, state)
            }
            Err(_) => (snapshot, "invalid"),
        }
    }
    pub fn save(&self, snapshot: &Snapshot) -> Result<()> {
        ensure!(wall_ms() >= snapshot.wall_highwater, "clock rollback");
        let (boot_id, uptime_ms) = (self.clock)()?;
        let now = Instant::now();
        let payload = Payload {
            version: 1,
            written_at_unix_ms: wall_ms(),
            boot_id,
            uptime_ms,
            // Retain expired IDs as tombstones so stale LAPI durations cannot
            // resurrect a decision after process restart (bounded by full sync).
            bans: snapshot
                .bans
                .iter()
                .map(|(id, ban)| Record {
                    id: *id,
                    network: ban.network.to_string(),
                    expires_at_unix_ms: ban.expires_at_unix_ms,
                    remaining_ms: ban.expires.saturating_duration_since(now).as_millis() as u64,
                })
                .collect(),
        };
        let payload = serde_json::to_string(&payload)?;
        let bytes = serde_json::to_vec(&Envelope {
            mac: self.mac(payload.as_bytes())?,
            payload,
        })?;
        ensure!(bytes.len() <= MAX_RESPONSE, "checkpoint too large");
        let mut nonce = [0; 16];
        openssl::rand::rand_bytes(&mut nonce)?;
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let temp = self.path.with_extension(format!("{suffix}.tmp"));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            std::fs::File::open(self.path.parent().context("checkpoint parent")?)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}
fn restore(
    payload: Payload,
    wall: u64,
    now: Instant,
    boot: &str,
    uptime: u64,
) -> Result<(HashMap<u64, Ban>, &'static str)> {
    ensure!(
        payload.version == 1 && payload.bans.len() <= MAX_DECISIONS,
        "invalid checkpoint version/size"
    );
    // Same-boot monotonic elapsed survives wall rollback. An ambiguous
    // cross-boot/backwards anchor cannot authorize active bans, but retain IDs
    // as expired tombstones so stale LAPI durations cannot resurrect them.
    let clock_invalid = (wall < payload.written_at_unix_ms && boot != payload.boot_id)
        || (boot == payload.boot_id && uptime < payload.uptime_ms);
    let elapsed = if clock_invalid {
        0
    } else if boot == payload.boot_id {
        uptime - payload.uptime_ms
    } else {
        wall - payload.written_at_unix_ms
    };
    let mut bans = HashMap::new();
    let mut active = 0;
    for record in payload.bans {
        ensure!(
            record.id > 0 && record.remaining_ms <= 366 * 86400 * 1000,
            "invalid decision"
        );
        let network: IpNet = record.network.parse()?;
        let remaining = if clock_invalid {
            0
        } else {
            record
                .remaining_ms
                .saturating_sub(elapsed)
                .min(record.expires_at_unix_ms.saturating_sub(wall))
        };
        active += usize::from(remaining > 0);
        ensure!(
            bans.insert(
                record.id,
                Ban {
                    network: network.trunc(),
                    expires: now + Duration::from_millis(remaining),
                    expires_at_unix_ms: record.expires_at_unix_ms
                }
            )
            .is_none(),
            "duplicate decision"
        );
    }
    Ok((
        bans,
        if clock_invalid {
            "clock_rollback"
        } else if active > 0 {
            if wall < payload.written_at_unix_ms {
                "loaded_clock_rollback"
            } else {
                "loaded"
            }
        } else {
            "stale"
        },
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn payload() -> Payload {
        Payload {
            version: 1,
            written_at_unix_ms: 10000,
            boot_id: "boot".into(),
            uptime_ms: 5000,
            bans: vec![Record {
                id: 1,
                network: "192.0.2.0/24".into(),
                expires_at_unix_ms: 12000,
                remaining_ms: 2000,
            }],
        }
    }
    #[test]
    fn expiry_clock_changes_and_tombstones() {
        let now = Instant::now();
        let (bans, state) = restore(payload(), 10500, now, "boot", 6500).unwrap();
        assert_eq!(state, "loaded");
        assert_eq!(bans[&1].expires, now + Duration::from_millis(500));
        let (rolled, state) = restore(payload(), 9999, now, "boot", 6500).unwrap();
        assert_eq!(state, "loaded_clock_rollback");
        assert_eq!(rolled[&1].expires, now + Duration::from_millis(500));
        let (invalid, state) = restore(payload(), 9999, now, "newboot", 100).unwrap();
        assert_eq!(state, "clock_rollback");
        assert_eq!(invalid[&1].expires, now);
        assert_eq!(
            restore(payload(), 15000, now, "newboot", 100).unwrap().1,
            "stale"
        );
        let (bans, _) = restore(payload(), 11000, now, "boot", 8000).unwrap();
        assert_eq!(bans[&1].expires, now);
    }
    #[test]
    fn atomic_roundtrip_integrity_permissions_and_bounds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let master = dir.path().join("key");
        std::fs::write(&master, [42; 32]).unwrap();
        std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut checkpoint = Checkpoint::new(dir.path().join("state"), &master).unwrap();
        // This test exercises filesystem/integrity, not Linux /proc. The clock
        // restore matrix above verifies restart/rollback independently.
        checkpoint.clock = || Ok(("fixture-boot".into(), 0));
        assert_eq!(checkpoint.load().1, "missing");
        let snapshot = apply(
            &super::super::tests::empty(),
            super::super::tests::response(1, "192.0.2.0/24", "1h"),
            Instant::now(),
        )
        .unwrap();
        checkpoint.save(&snapshot).unwrap();
        assert_eq!(checkpoint.load().1, "loaded");
        let mut data = std::fs::read(&checkpoint.path).unwrap();
        data[20] ^= 1;
        std::fs::write(&checkpoint.path, data).unwrap();
        assert_eq!(checkpoint.load().1, "invalid");
        checkpoint.save(&snapshot).unwrap();
        std::fs::set_permissions(&checkpoint.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(checkpoint.load().1, "invalid");
        let mut p = payload();
        p.version = 2;
        assert!(restore(p, 10000, Instant::now(), "boot", 5000).is_err());
        let mut p = payload();
        p.bans[0].remaining_ms = u64::MAX;
        assert!(restore(p, 10000, Instant::now(), "boot", 5000).is_err());
    }
}
