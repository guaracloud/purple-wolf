//! http-wasm host bindings used by the plugin entry points.
//!
//! Hand-rolled against the http-wasm Handler ABI (spec v0.0.0, `http_handler`
//! import module) as documented at <https://http-wasm.io/http-handler-abi/>
//! and implemented by the reference guest at
//! <https://github.com/http-wasm/http-wasm-guest-tinygo>. We surveyed the only
//! published Rust SDK — `http-wasm-guest` 0.11.3 by blndfsk
//! (<https://crates.io/crates/http-wasm-guest>) — and ruled it out for this
//! task because it requires Rust 1.85.1 / edition 2024 while this workspace
//! is pinned to 1.75 / edition 2021. Bumping the MSRV of the whole workspace
//! for a single transitive dependency is a worse trade than the small shim
//! below; the spec is ~20 imports and the variable-length read protocol is
//! straightforward. Imports are unconditional `extern "C"` declarations against
//! the `http_handler` module on wasm32, and replaced with native fallbacks on
//! host targets so the config-adapter (Task 16) and other native unit tests
//! can run end-to-end without a wasm runtime.

#![allow(dead_code)] // Task 17 wires the remaining helpers.

// ---------------------------------------------------------------------------
// ABI constants
// ---------------------------------------------------------------------------

/// http-wasm `header_kind` discriminator for the inbound request.
const KIND_REQUEST: i32 = 0;
/// http-wasm `header_kind` discriminator for the outbound response.
const KIND_RESPONSE: i32 = 1;

/// Largest single host buffer we'll ever allocate (16 MiB). Anything past this
/// is intentionally truncated to bound guest memory growth.
const MAX_ALLOC: usize = 0xFF_FFFF;

/// Starting size for the scratch buffer used by `read_buf` retry logic. Most
/// header/method/URI reads fit comfortably in this with one host call.
const SCRATCH: usize = 2048;

// ---------------------------------------------------------------------------
// Wasm imports
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod abi {
    #[link(wasm_import_module = "http_handler")]
    extern "C" {
        #[link_name = "log"]
        pub fn host_log(level: i32, buf: *const u8, len: i32);
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
/// side). Returns the first value if the header was sent multiple times.
pub fn get_request_header(name: &str) -> Option<String> {
    let values = header_values(KIND_REQUEST, name.as_bytes());
    values.into_iter().next().map(bytes_to_string_lossy)
}

/// Read at most `max` bytes of the request body (truncates at the cap).
///
/// The body is consumed from the host stream; pair this call with
/// [`request_body_exceeded`] which inspects the same cached read result. Both
/// share an internal cache keyed by `max` so callers may invoke them in any
/// order, but the host stream is only drained once per request.
pub fn read_request_body(max: usize) -> Vec<u8> {
    body_cache_get_or_drain(max).bytes.clone()
}

/// True iff the request body length exceeds `max` (i.e. [`read_request_body`]
/// truncated it). Reading the body and this predicate share state — see
/// [`read_request_body`].
pub fn request_body_exceeded(max: usize) -> bool {
    body_cache_get_or_drain(max).exceeded
}

/// `ip:port` form of the TCP peer the host saw.
pub fn get_source_addr() -> String {
    bytes_to_string_lossy(source_addr_bytes())
}

/// Write a response status + body and signal the host to stop further
/// processing. The "stop" signal is recorded in a guest-local flag because the
/// http-wasm ABI conveys it through the return value of `handle_request`; the
/// entry point added in Task 17 reads [`response_taken`] and returns
/// `next = false` when set.
pub fn write_response(status: u16, body: &[u8]) {
    set_status(status);
    write_body_response(body);
    mark_response_taken();
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
// Auxiliary surface used by the (still-to-be-written) Task 17 entry point.
// ---------------------------------------------------------------------------

/// True if [`write_response`] was called since [`reset_response_taken`].
pub fn response_taken() -> bool {
    response_taken_flag()
}

/// Clear the per-request response-taken flag. Called by the entry point at
/// the start of every `handle_request`.
pub fn reset_response_taken() {
    set_response_taken(false);
    body_cache_reset();
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
    let cap = byte_len.min(MAX_ALLOC);
    let mut big = vec![0u8; cap];
    // SAFETY: see `read_buf`.
    let packed = call(big.as_mut_ptr(), big.len() as i32);
    let (count, byte_len) = split_packed(packed);
    let byte_len = byte_len.min(cap);
    split_nul(&big[..byte_len], count)
}

#[cfg(target_arch = "wasm32")]
fn split_packed(n: i64) -> (usize, usize) {
    let count = (n >> 32) as i32;
    let len = n as i32;
    (count.max(0) as usize, len.max(0) as usize)
}

#[cfg(target_arch = "wasm32")]
fn split_nul(buf: &[u8], count: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(count);
    let mut start = 0usize;
    for (i, b) in buf.iter().enumerate() {
        if *b == 0 {
            out.push(buf[start..i].to_vec());
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
fn drain_request_body(max: usize) -> BodyRead {
    // Read until either (a) host signals EOF, (b) we have buffered `max`
    // bytes and one more probe confirms additional data, or (c) we hit the
    // MAX_ALLOC ceiling.
    //
    // NEW-H4 guard: the loop must also break on `(size == 0, eof == false)`.
    // The http-wasm spec doesn't forbid an interim empty read; without the
    // guard a non-EOF empty read keeps re-issuing forever and hangs the
    // request (and the wasm guest's request slot, leaking through to a
    // Traefik backend timeout).
    let chunk_size = SCRATCH;
    let mut out = Vec::with_capacity(max.min(SCRATCH));
    let mut scratch = vec![0u8; chunk_size];
    let mut exceeded = false;
    loop {
        // SAFETY: `scratch` is a valid exclusive writable buffer for the call.
        let packed =
            unsafe { abi::read_body(KIND_REQUEST, scratch.as_mut_ptr(), scratch.len() as i32) };
        let (eof, size) = split_eof(packed);
        let size = size.min(scratch.len());
        if out.len() < max {
            let take = (max - out.len()).min(size);
            out.extend_from_slice(&scratch[..take]);
            // If the host produced more than we wanted to keep, the body is
            // already past the cap; mark exceeded and stop reading further.
            if size > take {
                exceeded = true;
                break;
            }
        } else if size > 0 {
            exceeded = true;
            break;
        }
        if eof || out.len() >= MAX_ALLOC {
            break;
        }
        // NEW-H4: zero-progress guard. If the host returned 0 bytes AND
        // hasn't signalled EOF, there's nothing for us to do — looping
        // would just re-issue the empty read forever.
        if size == 0 {
            break;
        }
    }
    BodyRead {
        bytes: out,
        exceeded,
    }
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
fn drain_request_body(_max: usize) -> BodyRead {
    BodyRead {
        bytes: Vec::new(),
        exceeded: false,
    }
}

// ---------------------------------------------------------------------------
// Per-request state (response-taken flag + body read cache).
//
// The shim runs inside a single-threaded wasm guest, so `thread_local!` is
// sufficient. On native targets it is also correct, with the caveat that
// tests sharing the same thread should call `reset_response_taken` between
// scenarios — which Task 17's entry point already does at request start.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct BodyRead {
    bytes: Vec<u8>,
    exceeded: bool,
}

#[derive(Default)]
struct State {
    response_taken: bool,
    body: Option<(usize, BodyRead)>, // (max, result)
}

thread_local! {
    static STATE: std::cell::RefCell<State> = std::cell::RefCell::new(State::default());
}

fn response_taken_flag() -> bool {
    STATE.with(|s| s.borrow().response_taken)
}

fn set_response_taken(v: bool) {
    STATE.with(|s| s.borrow_mut().response_taken = v);
}

fn mark_response_taken() {
    set_response_taken(true);
}

fn body_cache_reset() {
    STATE.with(|s| s.borrow_mut().body = None);
}

fn body_cache_get_or_drain(max: usize) -> BodyRead {
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        if let Some((cached_max, ref body)) = state.body {
            // The host body stream is consumed by the first `read_body` loop,
            // so we deliberately ignore a changed `max` and return the cached
            // result. Callers should pick one cap per request from config and
            // stick with it; the debug-assert catches accidental drift in
            // tests without trapping in production wasm.
            debug_assert_eq!(
                cached_max, max,
                "body_cache: max changed within a single request (was {cached_max}, now {max}); the host stream is already drained, returning cached result"
            );
            return body.clone();
        }
        let fresh = drain_request_body(max);
        state.body = Some((max, fresh.clone()));
        fresh
    })
}
