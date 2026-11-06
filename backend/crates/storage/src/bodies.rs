//! Separate, bounded body recording. Raw bytes never enter ordinary telemetry.
//! A dedicated owned thread parses/redacts and writes history, outside Pingora.
use crate::{History, QueryError};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        mpsc,
    },
    thread,
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

pub const LIMIT: usize = 65536;
const CACHE: usize = 32;
const TTL_MS: u64 = 7 * 86400000;
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS openwaf_bodies_v1 (request_id String, observed_at_unix_ms UInt64, payload String, observed_at DateTime MATERIALIZED toDateTime(intDiv(observed_at_unix_ms, 1000))) ENGINE = MergeTree ORDER BY (request_id, observed_at_unix_ms) TTL observed_at + INTERVAL 7 DAY DELETE";
const DEFAULT_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "csrf_token",
];

#[derive(Clone, Serialize, Deserialize)]
pub struct Side {
    pub status: String,
    pub reason: Option<String>,
    pub content_type: Option<String>,
    pub bytes: u64,
    pub content: Option<String>,
}
impl Side {
    fn not_collected() -> Self {
        Self::state("unavailable", Some("not_collected"))
    }
    fn state(status: &str, reason: Option<&str>) -> Self {
        Self {
            status: status.into(),
            reason: reason.map(str::to_owned),
            content_type: None,
            bytes: 0,
            content: None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub request_id: String,
    pub observed_at_unix_ms: u64,
    pub request: Side,
    pub response: Side,
    #[serde(default = "Side::not_collected")]
    pub query: Side,
    /// History may fail while the redacted live copy remains available.
    pub persistence: String,
}
impl Record {
    /// Safe ordinary-telemetry representation, including for recovered records.
    pub fn marker(&self) -> Self {
        let mut value = self.clone();
        value.request.content = None;
        value.response.content = None;
        value.query.content = None;
        value
    }
}
#[derive(Clone, Copy)]
enum Format {
    Json,
    Form,
    Query,
}
pub struct Capture {
    side: Side,
    format: Option<Format>,
    data: Zeroizing<Vec<u8>>,
    complete: bool,
    _permit: Option<OwnedSemaphorePermit>,
}
impl Capture {
    fn new(enabled: bool, budget: &Arc<Semaphore>) -> Self {
        let permit = enabled
            .then(|| budget.clone().try_acquire_owned().ok())
            .flatten();
        let side = if !enabled {
            Side::state("disabled", None)
        } else if permit.is_none() {
            Side::state("dropped", Some("capture_capacity"))
        } else {
            Side::state("pending", None)
        };
        Self {
            side,
            format: None,
            data: Zeroizing::new(Vec::new()),
            complete: false,
            _permit: permit,
        }
    }
    /// Original URI query, independent of body type, encoding or completion.
    pub fn query(&mut self, query: Option<&str>) {
        if self.side.status != "pending" {
            return;
        }
        self.format = Some(Format::Query);
        self.side.content_type = Some("application/x-www-form-urlencoded".into());
        self.push(query.unwrap_or_default().as_bytes(), true);
        if self.data.is_empty() && self.side.status == "pending" {
            self.side.status = "empty".into();
            self._permit = None;
        }
    }
    pub fn suppress(&mut self, reason: &str) {
        if self.side.status == "pending" {
            self.skip(reason);
        }
    }
    fn skip(&mut self, reason: &str) {
        self.side.status = "skipped".into();
        self.side.reason = Some(reason.into());
        self.data = Zeroizing::new(Vec::new());
        self._permit = None;
    }
    pub fn headers(&mut self, headers: &http::HeaderMap, empty: bool) {
        if self.side.status != "pending" {
            return;
        }
        if empty {
            self.complete = true;
            self.side.status = "empty".into();
            self._permit = None;
            return;
        }
        if headers.contains_key("content-encoding")
            && (headers.get_all("content-encoding").iter().count() != 1
                || !headers
                    .get("content-encoding")
                    .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"identity")))
        {
            self.skip("content_encoding");
            return;
        }
        let parsed = (headers.get_all("content-type").iter().count() == 1)
            .then(|| {
                headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<mime::Mime>().ok())
            })
            .flatten();
        let Some(mime) = parsed else {
            self.skip("unsupported_content_type");
            return;
        };
        if mime
            .get_param("charset")
            .is_some_and(|v| !v.as_str().eq_ignore_ascii_case("utf-8"))
        {
            self.skip("unsupported_charset");
            return;
        }
        let essence = mime.essence_str();
        self.format = if mime.type_() == mime::APPLICATION
            && (mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON))
        {
            Some(Format::Json)
        } else if essence == "application/x-www-form-urlencoded" {
            Some(Format::Form)
        } else {
            None
        };
        // Keep only a canonical, bounded type, never arbitrary client parameters.
        if essence.len() <= 128 {
            self.side.content_type = Some(essence.into());
        }
        if self.format.is_none() {
            self.skip("unsupported_content_type");
        }
        if headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > LIMIT as u64)
        {
            self.skip("body_too_large");
        }
    }
    pub fn push(&mut self, bytes: &[u8], end: bool) {
        if matches!(self.side.status.as_str(), "disabled" | "empty") {
            return;
        }
        self.side.bytes = self.side.bytes.saturating_add(bytes.len() as u64);
        if self.side.status != "pending" || self.complete {
            return;
        }
        if bytes.len() > LIMIT.saturating_sub(self.data.len()) {
            self.skip(if matches!(self.format, Some(Format::Query)) {
                "query_too_large"
            } else {
                "body_too_large"
            });
            return;
        }
        self.data.extend_from_slice(bytes);
        self.complete |= end;
    }
    fn redact(mut self, fields: &[String]) -> Side {
        if self.side.status != "pending" {
            return self.side;
        }
        if !self.complete {
            self.skip("incomplete_body");
            return self.side;
        }
        if self.data.is_empty() {
            self.side.status = "empty".into();
            return self.side;
        }
        let text = std::str::from_utf8(&self.data).ok();
        let content = match (self.format, text) {
            (Some(Format::Json), Some(text)) => redact_json(text, fields),
            (Some(Format::Form | Format::Query), Some(text)) => redact_form(text, fields),
            _ => None,
        };
        match content {
            Some(content) if content.len() <= LIMIT => {
                self.side.status = "recorded".into();
                self.side.content = Some(content);
            }
            Some(_) => self.skip(if matches!(self.format, Some(Format::Query)) {
                "redacted_query_too_large"
            } else {
                "redacted_body_too_large"
            }),
            None => self.skip(if matches!(self.format, Some(Format::Query)) {
                "invalid_query"
            } else {
                "invalid_body"
            }),
        }
        self.side
    }
}
fn sensitive(name: &str, fields: &[String]) -> bool {
    DEFAULT_FIELDS.iter().any(|v| name.eq_ignore_ascii_case(v))
        || fields.iter().any(|v| name.eq_ignore_ascii_case(v))
}
fn redact_json(text: &str, fields: &[String]) -> Option<String> {
    fn visit(value: &mut serde_json::Value, fields: &[String]) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if sensitive(key, fields) {
                        *value = serde_json::Value::String("[REDACTED]".into());
                    } else {
                        visit(value, fields);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for value in items {
                    visit(value, fields);
                }
            }
            _ => {}
        }
    }
    // serde_json's default recursion limit bounds both parsing and traversal.
    let mut value: serde_json::Value = serde_json::from_str(text).ok()?;
    visit(&mut value, fields);
    serde_json::to_string(&value).ok()
}
fn redact_form(text: &str, fields: &[String]) -> Option<String> {
    fn decode(text: &str) -> Option<String> {
        let mut bytes = Vec::with_capacity(text.len());
        let mut iter = text.bytes();
        while let Some(b) = iter.next() {
            bytes.push(match b {
                b'+' => b' ',
                b'%' => {
                    let a = (iter.next()? as char).to_digit(16)?;
                    let b = (iter.next()? as char).to_digit(16)?;
                    (a * 16 + b) as u8
                }
                b => b,
            });
        }
        String::from_utf8(bytes).ok()
    }
    fn encode(text: &str) -> String {
        let mut out = String::new();
        for b in text.bytes() {
            if b.is_ascii_alphanumeric() || b"-._*".contains(&b) {
                out.push(b as char);
            } else if b == b' ' {
                out.push('+');
            } else {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    }
    let mut out = Vec::new();
    for pair in text.split('&').filter(|v| !v.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(key)?;
        let value = decode(value)?;
        out.push(format!(
            "{}={}",
            encode(&key),
            encode(if sensitive(&key, fields) {
                "[REDACTED]"
            } else {
                &value
            })
        ));
    }
    Some(out.join("&"))
}

struct Job {
    record: Record,
    request: Capture,
    response: Capture,
    query: Capture,
    fields: Vec<String>,
}
pub struct Recording {
    service: Arc<Service>,
    request_id: String,
    observed_at_unix_ms: u64,
    pub request: Capture,
    pub response: Capture,
    pub query: Capture,
    fields: Vec<String>,
}
impl Recording {
    pub fn finish(mut self, request_complete: bool, response_complete: bool) -> Record {
        // A clean transport EOF may have no final nonempty chunk.
        self.request.complete |= request_complete;
        self.response.complete |= response_complete;
        for capture in [&mut self.request, &mut self.response, &mut self.query] {
            if capture.side.status == "pending" && !capture.complete {
                capture.skip("incomplete_body");
            }
        }
        let mut record = Record {
            request_id: self.request_id,
            observed_at_unix_ms: self.observed_at_unix_ms,
            request: self.request.side.clone(),
            response: self.response.side.clone(),
            query: self.query.side.clone(),
            persistence: "pending".into(),
        };
        if record.request.status == "disabled"
            && record.response.status == "disabled"
            && record.query.status == "disabled"
        {
            record.persistence = "not_required".into();
            return record;
        }
        let marker = record.marker();
        let job = Job {
            record,
            request: self.request,
            response: self.response,
            query: self.query,
            fields: self.fields,
        };
        self.service.queued.fetch_add(1, Relaxed);
        if self.service.stopped.load(Relaxed) || self.service.sender.try_send(job).is_err() {
            self.service.queued.fetch_sub(1, Relaxed);
            self.service.dropped.fetch_add(1, Relaxed);
            let mut failed = marker;
            failed.persistence = "dropped".into();
            for side in [&mut failed.request, &mut failed.response, &mut failed.query] {
                if side.status == "pending" {
                    side.status = "dropped".into();
                    side.reason = Some("capture_queue_full_or_stopped".into());
                }
            }
            failed
        } else {
            // Contention can omit a live marker, never stall the proxy.
            if let Ok(mut cache) = self.service.cache.try_lock()
                && !cache.iter().any(|v| v.request_id == marker.request_id)
            {
                if cache.len() >= CACHE {
                    cache.pop_front();
                }
                cache.push_back(marker.clone());
            }
            marker
        }
    }
}

pub struct Service {
    sender: mpsc::SyncSender<Job>,
    budget: Arc<Semaphore>,
    cache: Mutex<VecDeque<Record>>,
    pub history: OnceLock<Arc<History>>,
    stopped: AtomicBool,
    dropped: AtomicU64,
    processed: AtomicU64,
    queued: AtomicU64,
}
impl Service {
    pub fn begin(
        self: &Arc<Self>,
        id: String,
        request: bool,
        response: bool,
        query: bool,
        fields: Vec<String>,
    ) -> Recording {
        let request = Capture::new(request, &self.budget);
        let response = Capture::new(response, &self.budget);
        let query = Capture::new(query, &self.budget);
        if request.side.status == "dropped"
            || response.side.status == "dropped"
            || query.side.status == "dropped"
        {
            self.dropped.fetch_add(1, Relaxed);
        }
        Recording {
            service: self.clone(),
            request_id: id,
            observed_at_unix_ms: openwaf_telemetry::now_ms(),
            request,
            response,
            query,
            fields,
        }
    }
    pub fn lookup(&self, id: &str) -> Option<Record> {
        let mut record = self
            .cache
            .lock()
            .ok()?
            .iter()
            .find(|v| v.request_id == id)
            .cloned()?;
        if openwaf_telemetry::now_ms().saturating_sub(record.observed_at_unix_ms) >= TTL_MS {
            for side in [&mut record.request, &mut record.response, &mut record.query] {
                side.content = None;
                if side.status != "disabled" {
                    side.status = "expired".into();
                    side.reason = Some("retention_expired".into());
                }
            }
        }
        Some(record)
    }
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({"active_buffers": 128 - self.budget.available_permits(), "buffer_limit":128, "queue_depth":self.queued.load(Relaxed), "dropped":self.dropped.load(Relaxed), "processed":self.processed.load(Relaxed)})
    }
    fn remember(&self, record: Record) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.retain(|v| v.request_id != record.request_id);
            if cache.len() >= CACHE {
                cache.pop_front();
            }
            cache.push_back(record);
        }
    }
}

pub struct Worker {
    pub service: Arc<Service>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Worker {
    pub fn start() -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(32);
        let service = Arc::new(Service {
            sender,
            budget: Arc::new(Semaphore::new(128)),
            cache: Mutex::new(VecDeque::new()),
            history: OnceLock::new(),
            stopped: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            processed: AtomicU64::new(0),
            queued: AtomicU64::new(0),
        });
        let owner = service.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(2)
            .enable_all()
            .build()?;
        let thread = thread::Builder::new()
            .name("body-recorder".into())
            .spawn(move || {
                let mut initialized = false;
                loop {
                    let first = if owner.stopped.load(Relaxed) {
                        receiver.try_recv().ok()
                    } else {
                        match receiver.recv_timeout(Duration::from_millis(100)) {
                            Ok(job) => Some(job),
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(_) => None,
                        }
                    };
                    let Some(first) = first else {
                        break;
                    };
                    let mut jobs = vec![first];
                    jobs.extend(receiver.try_iter().take(15));
                    owner.queued.fetch_sub(jobs.len() as u64, Relaxed);
                    let mut records = Vec::new();
                    for job in jobs {
                        let mut record = job.record;
                        record.request = job.request.redact(&job.fields);
                        record.response = job.response.redact(&job.fields);
                        record.query = job.query.redact(&job.fields);
                        owner.processed.fetch_add(1, Relaxed);
                        owner.remember(record.clone());
                        records.push(record);
                    }
                    let persistence = if let Some(history) = owner.history.get() {
                        runtime.block_on(async {
                            if !initialized {
                                initialized = history.execute(SCHEMA, String::new()).await.is_ok();
                            }
                            if initialized && history.write_bodies(&records).await.is_ok() {
                                "written"
                            } else {
                                "failed_or_uncertain"
                            }
                        })
                    } else {
                        "not_configured"
                    };
                    for mut record in records {
                        record.persistence = persistence.into();
                        if persistence != "written" {
                            owner.dropped.fetch_add(1, Relaxed);
                        }
                        owner.remember(record);
                    }
                }
                runtime.shutdown_timeout(Duration::from_secs(1));
            })?;
        Ok(Self {
            service,
            thread: Some(thread),
        })
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.service.stopped.store(true, Relaxed);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            eprintln!("body recorder shutdown failed");
        }
    }
}

impl History {
    async fn write_bodies(&self, records: &[Record]) -> Result<(), ()> {
        let mut body = String::new();
        for record in records {
            let mut stored = record.clone();
            stored.persistence = "written".into();
            let payload = serde_json::to_string(&stored).map_err(|_| ())?;
            body.push_str(&serde_json::json!({"request_id":record.request_id,"observed_at_unix_ms":record.observed_at_unix_ms,"payload":payload}).to_string());
            body.push('\n');
        }
        let reply = self.execute("INSERT INTO openwaf_bodies_v1 (request_id, observed_at_unix_ms, payload) FORMAT JSONEachRow", body).await?;
        if reply.is_empty() { Ok(()) } else { Err(()) }
    }
    pub async fn query_bodies(&self, id: &str) -> Result<Option<Record>, QueryError> {
        if !openwaf_telemetry::request_id::valid(id) {
            return Err(QueryError::Invalid);
        }
        let _permit = self
            .queries
            .clone()
            .try_acquire_owned()
            .map_err(|_| QueryError::Unavailable)?;
        let start = openwaf_telemetry::now_ms().saturating_sub(TTL_MS);
        let bytes = self.execute(&format!("SELECT payload FROM openwaf_bodies_v1 WHERE request_id = '{id}' AND observed_at_unix_ms > {start} ORDER BY observed_at_unix_ms DESC LIMIT 1 FORMAT JSON"), String::new()).await.map_err(|_| QueryError::Unavailable)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| QueryError::Unavailable)?;
        let data = value["data"].as_array().ok_or(QueryError::Unavailable)?;
        match data.first() {
            Some(row) => Ok(Some(
                serde_json::from_str(row["payload"].as_str().ok_or(QueryError::Unavailable)?)
                    .map_err(|_| QueryError::Unavailable)?,
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_independent_redacts_decoded_repeated_names_and_omits_payload_from_marker() {
        let worker = Worker::start().expect("worker");
        let service = worker.service.clone();
        let id = "c".repeat(64);
        let mut recording = service.begin(id.clone(), false, false, true, vec!["private".into()]);
        recording.query.query(Some("%74oken=must_not_persist&TOKEN=must_not_persist&private=must_not_persist&ok=a%26b&tag=one&tag=two&flag"));
        let marker = recording.finish(false, false);
        assert_eq!(marker.request.status, "disabled");
        assert_eq!(marker.response.status, "disabled");
        assert_eq!(marker.query.status, "pending");
        assert!(marker.query.content.is_none());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let result = loop {
            if let Some(record) = service.lookup(&id)
                && record.query.status == "recorded"
            {
                break record;
            }
            assert!(std::time::Instant::now() < deadline, "worker deadline");
            thread::sleep(Duration::from_millis(5));
        };
        let content = result.query.content.as_ref().expect("redacted query");
        assert!(!content.contains("must_not_persist"));
        assert!(content.contains("ok=a%26b&tag=one&tag=two&flag="));
        assert!(result.marker().query.content.is_none());
        drop(worker);
        let mut expired = service.lookup(&id).expect("live");
        expired.observed_at_unix_ms = openwaf_telemetry::now_ms() - TTL_MS;
        service.remember(expired);
        let expired = service.lookup(&id).expect("expired");
        assert_eq!(expired.query.status, "expired");
        assert!(expired.query.content.is_none());
    }

    #[test]
    fn query_bounds_empty_invalid_encoding_capacity_and_legacy_defaults() {
        for query in [None, Some("")] {
            let mut c = Capture::new(true, &Arc::new(Semaphore::new(1)));
            c.query(query);
            assert_eq!(c.redact(&[]).status, "empty");
        }
        for query in ["token=%ZZ", "token=%FF"] {
            let mut c = Capture::new(true, &Arc::new(Semaphore::new(1)));
            c.query(Some(query));
            let side = c.redact(&[]);
            assert_eq!(side.reason.as_deref(), Some("invalid_query"));
            assert!(side.content.is_none());
        }
        let query = format!("ok={}", "a".repeat(LIMIT - 3));
        let mut c = Capture::new(true, &Arc::new(Semaphore::new(1)));
        c.query(Some(&query));
        assert_eq!(c.redact(&[]).status, "recorded");
        let mut c = Capture::new(true, &Arc::new(Semaphore::new(1)));
        c.query(Some(&format!("{query}a")));
        assert_eq!(c.redact(&[]).reason.as_deref(), Some("query_too_large"));
        let mut c = Capture::new(true, &Arc::new(Semaphore::new(1)));
        c.query(Some(&vec!["token=x"; 5000].join("&")));
        let side = c.redact(&[]);
        assert_eq!(side.reason.as_deref(), Some("redacted_query_too_large"));
        assert!(side.content.is_none());
        let mut c = Capture::new(true, &Arc::new(Semaphore::new(0)));
        c.query(Some("ok=yes"));
        assert_eq!(c.redact(&[]).reason.as_deref(), Some("capture_capacity"));
        let side = serde_json::json!({"status":"disabled","reason":null,"content_type":null,"bytes":0,"content":null});
        let record: Record = serde_json::from_value(serde_json::json!({"request_id":"a".repeat(64),"observed_at_unix_ms":1,"request":side,"response":side,"persistence":"not_required"})).expect("legacy record");
        assert_eq!(record.query.status, "unavailable");
        assert_eq!(record.query.reason.as_deref(), Some("not_collected"));
    }

    fn service() -> (Arc<Service>, mpsc::Receiver<Job>) {
        let (sender, receiver) = mpsc::sync_channel(32);
        (
            Arc::new(Service {
                sender,
                budget: Arc::new(Semaphore::new(128)),
                cache: Mutex::new(VecDeque::new()),
                history: OnceLock::new(),
                stopped: AtomicBool::new(false),
                dropped: AtomicU64::new(0),
                processed: AtomicU64::new(0),
                queued: AtomicU64::new(0),
            }),
            receiver,
        )
    }

    #[test]
    fn capacity_and_queue_overflow_release_raw_buffers_without_payload_in_markers() {
        let (service, receiver) = service();
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().expect("header"));
        for index in 0..33 {
            let mut recording = service.begin(format!("{index:064x}"), true, false, false, vec![]);
            recording.request.headers(&headers, false);
            recording
                .request
                .push(br#"{"password":"must_not_persist"}"#, true);
            let marker = recording.finish(true, false);
            assert!(
                !serde_json::to_string(&marker)
                    .expect("marker")
                    .contains("must_not_persist")
            );
            assert!(marker.request.content.is_none());
            if index == 32 {
                assert_eq!(marker.request.status, "dropped");
            }
        }
        assert_eq!(service.queued.load(Relaxed), 32);
        assert_eq!(service.budget.available_permits(), 96);
        assert_eq!(service.dropped.load(Relaxed), 1);
        assert_eq!(service.cache.lock().expect("cache").len(), CACHE);
        drop(receiver);
        assert_eq!(service.budget.available_permits(), 128);

        let held = service
            .budget
            .clone()
            .try_acquire_many_owned(128)
            .expect("all capacity");
        let recording = service.begin("a".repeat(64), true, true, false, vec![]);
        assert_eq!(
            recording.request.side.reason.as_deref(),
            Some("capture_capacity")
        );
        assert_eq!(
            recording.response.side.reason.as_deref(),
            Some("capture_capacity")
        );
        drop(held);
    }

    #[test]
    fn exact_limit_split_secrets_compression_and_disabled_directions() {
        let body = format!(r#"{{"ok":"{}"}}"#, "a".repeat(LIMIT - 9));
        assert_eq!(body.len(), LIMIT);
        let mut c = capture("application/json");
        c.push(body.as_bytes(), true);
        assert_eq!(c.redact(&[]).status, "recorded");
        let mut c = capture("application/json");
        c.push(br#"{"password":"must_"#, false);
        c.push(br#"not_persist"}"#, true);
        let side = c.redact(&[]);
        assert!(!side.content.expect("redacted").contains("must_not_persist"));
        let mut c = Capture::new(true, &Arc::new(Semaphore::new(1)));
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().expect("header"));
        headers.insert("content-encoding", "gzip".parse().expect("header"));
        c.headers(&headers, false);
        c.push(b"not stored", true);
        assert_eq!(c.redact(&[]).reason.as_deref(), Some("content_encoding"));
        assert_eq!(
            capture("application/json; charset=iso-8859-1")
                .redact(&[])
                .reason
                .as_deref(),
            Some("unsupported_charset")
        );
        let mut c = Capture::new(false, &Arc::new(Semaphore::new(1)));
        c.push(b"not stored", true);
        assert_eq!(c.redact(&[]).status, "disabled");
        let mut c = capture("application/json");
        c.push(b"\xff", true);
        assert_eq!(c.redact(&[]).reason.as_deref(), Some("invalid_body"));
    }

    #[test]
    fn owned_worker_keeps_directions_independent_and_expires_live_content() {
        let worker = Worker::start().expect("worker");
        let service = worker.service.clone();
        let id = "b".repeat(64);
        let mut recording = service.begin(id.clone(), false, true, false, vec!["private".into()]);
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().expect("header"));
        recording.response.headers(&headers, false);
        recording
            .response
            .push(br#"{"private":"must_not_persist","ok":1}"#, true);
        let marker = recording.finish(false, true);
        assert_eq!(marker.request.status, "disabled");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let result = loop {
            if let Some(record) = service.lookup(&id)
                && record.response.status == "recorded"
            {
                break record;
            }
            assert!(std::time::Instant::now() < deadline, "worker deadline");
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(result.request.status, "disabled");
        assert!(
            !result
                .response
                .content
                .expect("redacted body")
                .contains("must_not_persist")
        );
        drop(worker); // joins the owner and releases reservations
        assert_eq!(service.budget.available_permits(), 128);
        let mut expired = service.lookup(&id).expect("live");
        expired.observed_at_unix_ms = openwaf_telemetry::now_ms() - TTL_MS;
        service.remember(expired);
        let expired = service.lookup(&id).expect("expired marker");
        assert_eq!(expired.response.status, "expired");
        assert!(expired.response.content.is_none());
    }
    #[test]
    fn secrets_are_redacted_in_nested_json_and_repeated_encoded_form_keys() {
        let fields = vec!["private".into()];
        let json = redact_json(
            r#"{"Password":"secret1","items":[{"token":"secret2","private":{"x":1},"ok":true}]}"#,
            &fields,
        )
        .expect("JSON");
        assert!(!json.contains("secret1") && !json.contains("secret2"));
        assert!(json.contains("[REDACTED]") && json.contains("true"));
        let form = redact_form(
            "%74oken=secret1&TOKEN=secret2&ok=a%26b&private=secret3",
            &fields,
        )
        .expect("form");
        assert!(!form.contains("secret"));
        assert!(form.contains("ok=a%26b"));
        assert!(redact_form("token=%ZZ", &fields).is_none());
        assert!(redact_form("x=%FF", &fields).is_none());
    }
    fn capture(content_type: &str) -> Capture {
        let mut capture = Capture::new(true, &Arc::new(Semaphore::new(1)));
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", content_type.parse().expect("header"));
        capture.headers(&headers, false);
        capture
    }
    #[test]
    fn only_complete_supported_bounded_bodies_are_saved() {
        let mut c = capture("application/problem+json; charset=utf-8");
        c.push(br#"{"token":"secret"}"#, true);
        let side = c.redact(&[]);
        assert_eq!(side.status, "recorded");
        assert!(!side.content.expect("body").contains("secret"));
        let mut c = capture("application/json");
        c.push(br#"{"token":"secret"}"#, false);
        assert_eq!(c.redact(&[]).reason.as_deref(), Some("incomplete_body"));
        let mut c = capture("application/json");
        c.push(&vec![b' '; LIMIT + 1], true);
        let side = c.redact(&[]);
        assert!(side.content.is_none());
        assert_eq!(side.reason.as_deref(), Some("body_too_large"));
        assert_eq!(capture("text/event-stream").redact(&[]).status, "skipped");
        assert_eq!(capture("multipart/form-data").redact(&[]).status, "skipped");
        let mut c = capture("application/json");
        c.push(b"not JSON", true);
        assert_eq!(c.redact(&[]).reason.as_deref(), Some("invalid_body"));
    }
}
