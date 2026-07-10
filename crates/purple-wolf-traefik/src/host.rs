//! http-wasm host bindings used by the plugin entry points.
//!
//! Hand-rolled against the http-wasm Handler ABI (spec v0.0.0, `http_handler`
//! import module) as documented at <https://http-wasm.io/http-handler-abi/>
//! and implemented by the reference guest at
//! <https://github.com/http-wasm/http-wasm-guest-tinygo>. We surveyed the only
//! published Rust SDK — `http-wasm-guest` 0.11.3 by blndfsk
//! (<https://crates.io/crates/http-wasm-guest>) — and kept this small shim to
//! avoid moving the workspace to edition 2024 for one adapter dependency.
//! Imports are unconditional `extern "C"` declarations against the
//! `http_handler` module on wasm32, and replaced with native fallbacks on host
//! targets so config-adapter unit tests can run without a wasm runtime.

// ---------------------------------------------------------------------------
// ABI constants
// ---------------------------------------------------------------------------

/// http-wasm `header_kind` discriminator for the inbound request.
const KIND_REQUEST: i32 = 0;
/// http-wasm `header_kind` discriminator for the outbound response.
#[cfg(target_arch = "wasm32")]
const KIND_RESPONSE: i32 = 1;
/// Preserve a request body for the downstream handler after guest inspection.
#[cfg(target_arch = "wasm32")]
const FEATURE_BUFFER_REQUEST: i32 = 1;

/// Largest aggregate host value or inspected body prefix we'll allocate in the
/// guest (16 MiB). Anything past this is intentionally truncated or rejected.
#[cfg(any(target_arch = "wasm32", test))]
const MAX_ALLOC: usize = 0xFF_FFFF;

/// Starting size for the scratch buffer used by `read_buf` retry logic. Most
/// header/method/URI reads fit comfortably in this with one host call.
#[cfg(any(target_arch = "wasm32", test))]
const SCRATCH: usize = 2048;
/// Bound the number of NUL-delimited header names/values materialized from one
/// host call. This remains well above the structural detector's 100-header
/// threshold while preventing a tiny all-NUL buffer from allocating millions
/// of empty vectors.
#[cfg(any(target_arch = "wasm32", test))]
const MAX_MULTI_VALUES: usize = 1024;

// ---------------------------------------------------------------------------
// Wasm imports
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod abi {
    #[link(wasm_import_module = "http_handler")]
    extern "C" {
        #[link_name = "log"]
        pub fn host_log(level: i32, buf: *const u8, len: i32);
        pub fn enable_features(features: i32) -> i32;
        pub fn get_config(buf: *mut u8, buf_limit: i32) -> i32;
        pub fn get_method(buf: *mut u8, buf_limit: i32) -> i32;
        pub fn get_uri(buf: *mut u8, buf_limit: i32) -> i32;
        pub fn get_source_addr(buf: *mut u8, buf_limit: i32) -> i32;
        pub fn get_header_names(kind: i32, buf: *mut u8, buf_limit: i32) -> i64;
        pub fn get_header_values(
            kind: i32,
            name: *const u8,
            name_len: i32,
            buf: *mut u8,
            buf_limit: i32,
        ) -> i64;
        pub fn read_body(kind: i32, buf: *mut u8, buf_limit: i32) -> i64;
        pub fn write_body(kind: i32, body: *const u8, len: i32);
        pub fn set_status_code(code: i32);
    }
}

// ---------------------------------------------------------------------------
// Public API (signatures pinned by Task 15 spec)
// ---------------------------------------------------------------------------

/// HTTP method of the inspected request.
pub fn get_method() -> String {
    bytes_to_string_lossy(method_bytes())
}

/// Path + query string of the inspected request.
pub fn get_uri() -> String {
    bytes_to_string_lossy(uri_bytes())
}

/// All request header names (case as Traefik delivered them).
pub fn get_request_header_names() -> Vec<String> {
    header_names(KIND_REQUEST)
        .into_iter()
        .map(bytes_to_string_lossy)
        .collect()
}

/// Value of a single request header by name (case-insensitive on the host
/// side). When the header was sent multiple times, all values are joined
/// with `", "` per RFC 7230 §3.2.2; this matters for inspection because
/// an attacker could otherwise hide a payload in the second of two
/// duplicate headers (NEW-I3 in the followup review).
pub fn get_request_header(name: &str) -> Option<String> {
    let values = header_values(KIND_REQUEST, name.as_bytes());
    if values.is_empty() {
        return None;
    }
    let joined = values
        .into_iter()
        .map(bytes_to_string_lossy)
        .collect::<Vec<_>>()
        .join(", ");
    Some(joined)
}

/// Read at most `max` bytes of the request body into guest memory and return
/// both the buffered prefix and whether more bytes existed.
///
/// Every byte read is also streamed back through the ABI request-body writer
/// so the downstream handler receives the original body. When
/// `preserve_after_cap` is true, reading continues after the inspection cap
/// without retaining those bytes in guest memory. When false, the first
/// overflow chunk returns immediately so `overCap=block` can reject early.
pub fn read_request_body(max: usize, preserve_after_cap: bool) -> Result<BodyRead, BodyReadError> {
    if !enable_request_buffering() {
        return Err(BodyReadError::BufferingUnsupported);
    }
    drain_request_body(max, preserve_after_cap)
}

/// `ip:port` form of the TCP peer the host saw.
pub fn get_source_addr() -> String {
    bytes_to_string_lossy(source_addr_bytes())
}

/// Write a response status + body and signal the host to stop further
/// processing. The entry point returns the ABI's `next = false` signal after
/// calling this helper.
pub fn write_response(status: u16, body: &[u8]) {
    set_status(status);
    write_body_response(body);
}

/// Emit a single log line via the host's log sink (`info` level).
pub fn log(message: &str) {
    log_bytes(LogLevel::Info, message.as_bytes());
}

/// Raw plugin config bytes Traefik passed in (JSON).
pub fn config() -> Vec<u8> {
    config_bytes()
}

// ---------------------------------------------------------------------------
// Log levels mirror http-wasm spec values.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[repr(i32)]
enum LogLevel {
    Debug = -1,
    Info = 0,
    Warn = 1,
    Error = 2,
}

// ---------------------------------------------------------------------------
// Variable-length read helpers (wasm-only; native fallbacks bypass them).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
fn read_buf(mut call: impl FnMut(*mut u8, i32) -> i32) -> Vec<u8> {
    let mut buf = vec![0u8; SCRATCH];
    // SAFETY: `buf` is a valid, exclusive, properly-sized writable slice of
    // length `buf.len()`; the host writes at most `buf_limit` bytes and
    // returns the true length the request would have needed.
    let needed = call(buf.as_mut_ptr(), buf.len() as i32);
    let needed = needed.max(0) as usize;
    if needed <= buf.len() {
        buf.truncate(needed);
        return buf;
    }
    // NEW-H5 guard: if the host asks for more than our hard cap, a second
    // call with `buf_limit < needed` would (per http-wasm spec) cause the
    // host to write nothing and return the same huge `needed` again — we'd
    // then hand back MAX_ALLOC bytes of zeros as if they were real data.
    // Truncate the request honestly instead and log so the operator can
    // see the underrun in audit logs.
    if needed > MAX_ALLOC {
        log_bytes(
            LogLevel::Warn,
            format!(
                "purple-wolf: host requested {needed} bytes for a single read, exceeds MAX_ALLOC={MAX_ALLOC}; returning empty buffer rather than risk zero-padded data"
            )
            .as_bytes(),
        );
        return Vec::new();
    }
    let cap = needed;
    let mut big = vec![0u8; cap];
    // SAFETY: same invariants as the first call; buffer is sized to the host's
    // requested length (no longer clamped, since needed <= MAX_ALLOC).
    let actual = call(big.as_mut_ptr(), big.len() as i32);
    let actual = actual.max(0) as usize;
    // Defense in depth: if a misbehaving host still reports more than the
    // buffer we just gave it, refuse to forward the contents rather than
    // pass uninitialized/zeroed bytes downstream.
    if actual > cap {
        log_bytes(
            LogLevel::Warn,
            b"purple-wolf: host returned more bytes than buf_limit on retry; discarding",
        );
        return Vec::new();
    }
    big.truncate(actual);
    big
}

/// Read a NUL-delimited multi-value buffer. The host return value packs
/// `count` in the high 32 bits and `byte_len` in the low 32.
#[cfg(target_arch = "wasm32")]
fn read_buf_multi(mut call: impl FnMut(*mut u8, i32) -> i64) -> Vec<Vec<u8>> {
    let mut buf = vec![0u8; SCRATCH];
    // SAFETY: see `read_buf`.
    let packed = call(buf.as_mut_ptr(), buf.len() as i32);
    let (count, byte_len) = split_packed(packed);
    if byte_len <= buf.len() {
        return split_nul(&buf[..byte_len], count);
    }
    // As with `read_buf`, retrying below the host-reported length writes
    // nothing by ABI contract. Treat an oversized aggregate as unavailable
    // instead of scanning a MAX_ALLOC-sized zero buffer into empty values.
    if byte_len > MAX_ALLOC {
        log_bytes(
            LogLevel::Warn,
            format!(
                "purple-wolf: host requested {byte_len} bytes for a multi-value read, exceeds MAX_ALLOC={MAX_ALLOC}; discarding"
            )
            .as_bytes(),
        );
        return Vec::new();
    }
    let cap = byte_len;
    let mut big = vec![0u8; cap];
    // SAFETY: see `read_buf`.
    let packed = call(big.as_mut_ptr(), big.len() as i32);
    let (count, byte_len) = split_packed(packed);
    if byte_len > cap {
        log_bytes(
            LogLevel::Warn,
            b"purple-wolf: host returned more multi-value bytes than buf_limit on retry; discarding",
        );
        return Vec::new();
    }
    split_nul(&big[..byte_len], count)
}

#[cfg(target_arch = "wasm32")]
fn split_packed(n: i64) -> (usize, usize) {
    let count = (n >> 32) as i32;
    let len = n as i32;
    (count.max(0) as usize, len.max(0) as usize)
}

#[cfg(any(target_arch = "wasm32", test))]
fn split_nul(buf: &[u8], count: usize) -> Vec<Vec<u8>> {
    let count = count.min(MAX_MULTI_VALUES);
    if count == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count.min(buf.len()));
    let mut start = 0usize;
    for (i, b) in buf.iter().enumerate() {
        if *b == 0 {
            out.push(buf[start..i].to_vec());
            if out.len() == count {
                break;
            }
            start = i + 1;
        }
    }
    out
}

#[cfg(target_arch = "wasm32")]
fn split_eof(n: i64) -> (bool, usize) {
    let eof = (n >> 32) as i32 != 0;
    let size = (n as i32).max(0) as usize;
    (eof, size)
}

fn bytes_to_string_lossy(b: Vec<u8>) -> String {
    // Avoid `from_utf8(...).unwrap()` — Traefik can forward non-UTF8 in odd
    // edge cases and we never want a guest panic from a malformed header.
    String::from_utf8_lossy(&b).into_owned()
}

// ---------------------------------------------------------------------------
// wasm32 wrappers around the raw imports
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
fn method_bytes() -> Vec<u8> {
    // SAFETY: `get_method` is the http-wasm import obeying the
    // `(buf, buf_limit) -> needed` contract; `read_buf` only forwards a valid
    // exclusive buffer of `buf_limit` bytes.
    read_buf(|p, l| unsafe { abi::get_method(p, l) })
}

#[cfg(target_arch = "wasm32")]
fn uri_bytes() -> Vec<u8> {
    // SAFETY: same as `method_bytes`.
    read_buf(|p, l| unsafe { abi::get_uri(p, l) })
}

#[cfg(target_arch = "wasm32")]
fn source_addr_bytes() -> Vec<u8> {
    // SAFETY: same as `method_bytes`.
    read_buf(|p, l| unsafe { abi::get_source_addr(p, l) })
}

#[cfg(target_arch = "wasm32")]
fn config_bytes() -> Vec<u8> {
    // SAFETY: same as `method_bytes`.
    read_buf(|p, l| unsafe { abi::get_config(p, l) })
}

#[cfg(target_arch = "wasm32")]
fn header_names(kind: i32) -> Vec<Vec<u8>> {
    // SAFETY: `get_header_names` is the http-wasm multi-value import. The
    // returned i64 packs (count, byte_len) and the buffer holds NUL-delimited
    // names — `read_buf_multi` handles both invariants.
    read_buf_multi(|p, l| unsafe { abi::get_header_names(kind, p, l) })
}

#[cfg(target_arch = "wasm32")]
fn header_values(kind: i32, name: &[u8]) -> Vec<Vec<u8>> {
    let name_ptr = name.as_ptr();
    let name_len = name.len() as i32;
    // SAFETY: see `header_names`; the host also reads `(name_ptr, name_len)`
    // which is a valid borrow for the duration of the call.
    read_buf_multi(|p, l| unsafe { abi::get_header_values(kind, name_ptr, name_len, p, l) })
}

#[cfg(target_arch = "wasm32")]
fn set_status(status: u16) {
    // SAFETY: thin pass-through of an FFI scalar; no pointers involved.
    unsafe { abi::set_status_code(status as i32) }
}

#[cfg(target_arch = "wasm32")]
fn write_body_response(body: &[u8]) {
    // SAFETY: `body` is a valid readable slice for the call duration; the
    // host treats it as read-only input.
    unsafe { abi::write_body(KIND_RESPONSE, body.as_ptr(), body.len() as i32) }
}

#[cfg(target_arch = "wasm32")]
fn log_bytes(level: LogLevel, msg: &[u8]) {
    // SAFETY: `msg` is a valid readable slice for the call duration.
    unsafe { abi::host_log(level as i32, msg.as_ptr(), msg.len() as i32) }
}

#[cfg(target_arch = "wasm32")]
fn drain_request_body(max: usize, preserve_after_cap: bool) -> Result<BodyRead, BodyReadError> {
    drain_body(
        max,
        preserve_after_cap,
        |scratch| {
            // SAFETY: `scratch` is a valid exclusive writable buffer for the call.
            let packed =
                unsafe { abi::read_body(KIND_REQUEST, scratch.as_mut_ptr(), scratch.len() as i32) };
            split_eof(packed)
        },
        |chunk| {
            // SAFETY: `chunk` is readable for the call duration. The first
            // request-body write replaces the consumed body; later writes
            // append, reconstructing it without retaining it all in the guest.
            unsafe { abi::write_body(KIND_REQUEST, chunk.as_ptr(), chunk.len() as i32) }
        },
    )
}

// ---------------------------------------------------------------------------
// Native fallbacks. Allow the crate's native unit tests (Task 16) to exercise
// the config-adapter without a wasm runtime. Most fallbacks are minimal.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
fn method_bytes() -> Vec<u8> {
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
fn uri_bytes() -> Vec<u8> {
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
fn source_addr_bytes() -> Vec<u8> {
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
fn header_names(_kind: i32) -> Vec<Vec<u8>> {
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
fn header_values(_kind: i32, _name: &[u8]) -> Vec<Vec<u8>> {
    Vec::new()
}

#[cfg(not(target_arch = "wasm32"))]
fn set_status(_status: u16) {}

#[cfg(not(target_arch = "wasm32"))]
fn write_body_response(_body: &[u8]) {}

#[cfg(not(target_arch = "wasm32"))]
fn log_bytes(_level: LogLevel, msg: &[u8]) {
    eprintln!("[purple-wolf-traefik] {}", String::from_utf8_lossy(msg));
}

#[cfg(not(target_arch = "wasm32"))]
fn config_bytes() -> Vec<u8> {
    // Tests can preload config via the `PURPLE_WOLF_PLUGIN_CONFIG` env var
    // (raw JSON). This is the same wire format Traefik passes through
    // `get_config`, which keeps the Task 16 adapter test surface honest.
    std::env::var("PURPLE_WOLF_PLUGIN_CONFIG")
        .map(String::into_bytes)
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
fn drain_request_body(_max: usize, _preserve_after_cap: bool) -> Result<BodyRead, BodyReadError> {
    Ok(BodyRead {
        bytes: Vec::new(),
        exceeded: false,
    })
}

#[cfg(target_arch = "wasm32")]
fn enable_request_buffering() -> bool {
    // SAFETY: scalar-only http-wasm ABI call. The return value is the full
    // supported-feature bitset, so test the requested bit explicitly.
    unsafe { abi::enable_features(FEATURE_BUFFER_REQUEST) & FEATURE_BUFFER_REQUEST != 0 }
}

#[cfg(not(target_arch = "wasm32"))]
fn enable_request_buffering() -> bool {
    true
}

/// Read a request body prefix with bounded guest memory.
///
/// The scratch space lives on the stack and the output vector stays
/// unallocated for an empty body. A bounded number of zero-progress reads is
/// tolerated because the ABI permits `(len=0, eof=false)`, but an indefinitely
/// stalled host is reported as an inspection error instead of hanging a guest.
#[cfg(any(target_arch = "wasm32", test))]
fn drain_body(
    max: usize,
    preserve_after_cap: bool,
    mut read: impl FnMut(&mut [u8]) -> (bool, usize),
    mut preserve: impl FnMut(&[u8]),
) -> Result<BodyRead, BodyReadError> {
    const MAX_EMPTY_READS: usize = 3;

    let limit = max.min(MAX_ALLOC);
    let mut out = Vec::new();
    let mut scratch = [0_u8; SCRATCH];
    let mut empty_reads = 0;
    let mut exceeded = false;

    loop {
        let (eof, size) = read(&mut scratch);
        if size > scratch.len() {
            return Err(BodyReadError::HostContractViolation);
        }

        if size == 0 {
            if eof {
                return Ok(BodyRead {
                    bytes: out,
                    exceeded,
                });
            }
            empty_reads += 1;
            if empty_reads >= MAX_EMPTY_READS {
                return Err(BodyReadError::StreamStalled);
            }
            continue;
        }
        empty_reads = 0;
        preserve(&scratch[..size]);

        let remaining = limit.saturating_sub(out.len());
        let take = remaining.min(size);
        out.extend_from_slice(&scratch[..take]);
        if size > take {
            exceeded = true;
            if !preserve_after_cap {
                return Ok(BodyRead {
                    bytes: out,
                    exceeded,
                });
            }
        }
        if eof {
            return Ok(BodyRead {
                bytes: out,
                exceeded,
            });
        }
        // When `out` is exactly at the limit, make one more read. A positive
        // result proves truncation; EOF proves a body exactly equal to the cap.
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BodyRead {
    pub bytes: Vec<u8>,
    pub exceeded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyReadError {
    BufferingUnsupported,
    #[cfg(any(target_arch = "wasm32", test))]
    StreamStalled,
    #[cfg(any(target_arch = "wasm32", test))]
    HostContractViolation,
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            BodyReadError::BufferingUnsupported => {
                "http-wasm host does not support request-body buffering"
            }
            #[cfg(any(target_arch = "wasm32", test))]
            BodyReadError::StreamStalled => "http-wasm request-body stream made no progress",
            #[cfg(any(target_arch = "wasm32", test))]
            BodyReadError::HostContractViolation => {
                "http-wasm host returned a body chunk larger than the supplied buffer"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for BodyReadError {}

impl BodyReadError {
    /// Whether applying `fail_open` can still forward the original request.
    /// Feature negotiation fails before reading; other errors may happen after
    /// incremental body reconstruction has begun and must fail closed.
    pub fn forwarding_is_safe(self) -> bool {
        matches!(self, BodyReadError::BufferingUnsupported)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{drain_body, split_nul, BodyRead, BodyReadError, MAX_MULTI_VALUES};
    use std::collections::VecDeque;

    fn reader(
        chunks: impl IntoIterator<Item = (bool, &'static [u8])>,
    ) -> impl FnMut(&mut [u8]) -> (bool, usize) {
        let mut chunks: VecDeque<_> = chunks.into_iter().collect();
        move |buf| {
            let (eof, bytes) = chunks.pop_front().expect("unexpected extra read");
            buf[..bytes.len()].copy_from_slice(bytes);
            (eof, bytes.len())
        }
    }

    #[test]
    fn empty_body_does_not_allocate_output() {
        let body = drain_body(1024, true, reader([(true, b"".as_slice())]), |_| {}).unwrap();
        assert_eq!(body, BodyRead::default());
        assert_eq!(body.bytes.capacity(), 0);
    }

    #[test]
    fn exact_cap_is_not_reported_as_exceeded() {
        let body = drain_body(
            4,
            true,
            reader([(false, b"abcd".as_slice()), (true, b"".as_slice())]),
            |_| {},
        )
        .unwrap();
        assert_eq!(body.bytes, b"abcd");
        assert!(!body.exceeded);
    }

    #[test]
    fn over_cap_body_returns_only_the_prefix() {
        let body = drain_body(4, false, reader([(false, b"abcdef".as_slice())]), |_| {}).unwrap();
        assert_eq!(body.bytes, b"abcd");
        assert!(body.exceeded);
    }

    #[test]
    fn bounded_zero_progress_becomes_an_error() {
        let error = drain_body(
            4,
            true,
            reader([
                (false, b"".as_slice()),
                (false, b"".as_slice()),
                (false, b"".as_slice()),
            ]),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error, BodyReadError::StreamStalled);
    }

    #[test]
    fn transient_zero_progress_is_tolerated() {
        let body = drain_body(
            4,
            true,
            reader([
                (false, b"".as_slice()),
                (false, b"ab".as_slice()),
                (true, b"cd".as_slice()),
            ]),
            |_| {},
        )
        .unwrap();
        assert_eq!(body.bytes, b"abcd");
        assert!(!body.exceeded);
    }

    #[test]
    fn pass_policy_reconstructs_bytes_beyond_the_inspection_cap() {
        let mut preserved = Vec::new();
        let body = drain_body(
            4,
            true,
            reader([
                (false, b"abcd".as_slice()),
                (false, b"efgh".as_slice()),
                (true, b"ij".as_slice()),
            ]),
            |chunk| preserved.extend_from_slice(chunk),
        )
        .unwrap();
        assert_eq!(body.bytes, b"abcd");
        assert!(body.exceeded);
        assert_eq!(preserved, b"abcdefghij");
    }

    #[test]
    fn nul_split_never_exceeds_the_host_reported_count() {
        let values = split_nul(b"a\0b\0c\0", 2);
        assert_eq!(values, [b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn nul_split_capacity_is_bounded_by_the_available_bytes() {
        let values = split_nul(b"a\0", usize::MAX);
        assert_eq!(values, [b"a".to_vec()]);
        assert!(values.capacity() <= 2);
    }

    #[test]
    fn nul_split_caps_adversarial_value_counts() {
        let bytes = vec![0_u8; MAX_MULTI_VALUES * 2];
        let values = split_nul(&bytes, usize::MAX);
        assert_eq!(values.len(), MAX_MULTI_VALUES);
        assert!(values.capacity() <= MAX_MULTI_VALUES);
    }
}
