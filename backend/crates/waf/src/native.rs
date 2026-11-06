//! Private FFI boundary. No native pointers cross thread or async boundaries.
use crate::{Configuration, Decision, Error, Finding, Report, Request};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
    sync::RwLock,
};

#[repr(C)]
struct Header {
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
}

#[repr(C)]
#[derive(Default)]
struct NativeReport {
    findings: [Finding; 32],
    count: u32,
    truncated: u32,
    body_inspected: u32,
}
// ModSecurity 3.0.9 initializes/cleans process-global curl/libxml resources.
// Lifecycle calls must not overlap each other or any native transaction. Read
// guards permit parallel inspections; only startup/cleanup needs exclusive access.
static NATIVE_LIFECYCLE: RwLock<()> = RwLock::new(());

unsafe extern "C" {
    fn ow_engine_policy_new(
        path: *const c_char,
        mode: c_int,
        paranoia: u32,
        exclusions: *const u32,
        count: usize,
    ) -> *mut c_void;
    fn ow_engine_exception(
        engine: *mut c_void,
        rule_id: u32,
        target: *const c_char,
        expires_ms: u64,
    ) -> c_int;
    fn ow_engine_free(engine: *mut c_void);
    fn ow_inspect(
        engine: *mut c_void,
        uri: *const c_char,
        method: *const c_char,
        version: *const c_char,
        client: *const c_char,
        client_port: c_int,
        server: *const c_char,
        server_port: c_int,
        headers: *const Header,
        header_count: usize,
        body: *const u8,
        body_len: usize,
        inspect_body: c_int,
        report: *mut NativeReport,
    ) -> c_int;
}

// Rc marker deliberately makes Engine !Send and !Sync. Construct/drop on worker.
pub(super) struct Engine {
    ptr: NonNull<c_void>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Engine {
    pub(super) fn new(path: &str, configuration: &Configuration) -> Result<Self, Error> {
        let _lifecycle = NATIVE_LIFECYCLE
            .write()
            .map_err(|_| Error::Initialization)?;
        let path = CString::new(path).map_err(|_| Error::InvalidInput)?;
        // SAFETY: path is NUL-terminated and lives through the synchronous call.
        // The adapter either returns sole ownership or cleans all partial state.
        // Configuration validation bounds the integer array and paranoia level;
        // C borrows that array only for this call, parses generated text, and
        // copies parsed rules. No caller allocation is freed by native code.
        let ptr = unsafe {
            ow_engine_policy_new(
                path.as_ptr(),
                configuration.mode as c_int,
                configuration.paranoia_level.into(),
                configuration.exclusions.as_ptr(),
                configuration.exclusions.len(),
            )
        };
        let ptr = NonNull::new(ptr).ok_or(Error::Initialization)?;
        for exception in &configuration.exceptions {
            let target = CString::new(exception.target.as_deref().unwrap_or(""))
                .map_err(|_| Error::InvalidInput)?;
            // SAFETY: live worker-owned engine; target is borrowed only during
            // this synchronous call and copied by C++. Failure releases engine.
            if unsafe {
                ow_engine_exception(
                    ptr.as_ptr(),
                    exception.rule_id,
                    target.as_ptr(),
                    exception.expires_at_unix_ms.unwrap_or(0),
                )
            } != 0
            {
                // SAFETY: sole pointer, no live transactions, same owner thread.
                unsafe { ow_engine_free(ptr.as_ptr()) };
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            ptr,
            _thread_bound: PhantomData,
        })
    }

    pub(super) fn inspect(&mut self, request: &Request) -> Result<Report, Error> {
        let _lifecycle = NATIVE_LIFECYCLE.read().map_err(|_| Error::Inspection)?;
        let uri = CString::new(request.uri.as_str()).map_err(|_| Error::InvalidInput)?;
        let method = CString::new(request.method.as_str()).map_err(|_| Error::InvalidInput)?;
        let version = CString::new(request.version.as_str()).map_err(|_| Error::InvalidInput)?;
        let client =
            CString::new(request.client.ip().to_string()).map_err(|_| Error::InvalidInput)?;
        let server =
            CString::new(request.server.ip().to_string()).map_err(|_| Error::InvalidInput)?;
        let headers: Vec<_> = request
            .headers
            .iter()
            .map(|(name, value)| Header {
                name: name.as_ptr(),
                name_len: name.len(),
                value: value.as_ptr(),
                value_len: value.len(),
            })
            .collect();
        // SAFETY: Engine has sole ownership on this OS thread. All pointers refer
        // to immutable buffers that live for the entire synchronous call. The C
        // adapter consumes lengths, retains no Rust pointer, owns/cleans its tx,
        // and frees intervention strings with the native allocator before return.
        // NativeReport matches ow_report exactly; C writes only this borrowed
        // stack allocation. body_inspected is a scalar, never a native pointer.
        let mut report = NativeReport::default();
        let result = unsafe {
            ow_inspect(
                self.ptr.as_ptr(),
                uri.as_ptr(),
                method.as_ptr(),
                version.as_ptr(),
                client.as_ptr(),
                request.client.port().into(),
                server.as_ptr(),
                request.server.port().into(),
                headers.as_ptr(),
                headers.len(),
                request.body.as_ptr(),
                request.body.len(),
                i32::from(request.inspect_body),
                &mut report,
            )
        };
        match result {
            0 | 403 => Ok(Report {
                decision: if result == 403 {
                    Decision::Block
                } else {
                    Decision::Allow
                },
                findings: report.findings[..(report.count as usize).min(32)].to_vec(),
                truncated: report.truncated != 0,
                anomaly_score: None,
                body_inspected: report.body_inspected != 0,
            }),
            _ => Err(Error::Inspection),
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Even if a previous Rust caller panicked, native cleanup must be ordered.
        let _lifecycle = NATIVE_LIFECYCLE
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: sole owned pointer, dropped exactly once on its creating worker
        // after the last inspection, with no live transaction or borrowed pointer.
        unsafe { ow_engine_free(self.ptr.as_ptr()) };
    }
}
