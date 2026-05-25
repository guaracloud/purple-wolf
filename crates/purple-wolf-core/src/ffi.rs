//! FFI bindings for vendored libinjection. This is the only `unsafe` boundary.

use std::os::raw::{c_char, c_int};

extern "C" {
    /// Returns 1 if `input` looks like SQL injection. `fingerprint` must be a
    /// buffer of at least 8 bytes; libinjection writes the matched fingerprint.
    fn libinjection_sqli(input: *const c_char, slen: usize, fingerprint: *mut c_char) -> c_int;

    /// Returns 1 if `input` looks like cross-site scripting.
    fn libinjection_xss(input: *const c_char, slen: usize) -> c_int;
}

/// Safe wrapper: is `s` SQL injection?
///
/// Takes raw bytes (not `&str`) so non-UTF-8 payloads — e.g. a SQLi
/// crafted in SHIFT-JIS or any high-bit encoding — reach libinjection
/// in their original byte sequence. libinjection's C API is
/// byte-oriented; the previous `&str` signature forced a lossy
/// conversion at every call site that masked attacks (NEW-I2 in the
/// followup review).
pub fn is_sqli(s: &[u8]) -> bool {
    // `c_char` is `i8` on most targets but `u8` on aarch64 Linux; using
    // `0 as c_char` keeps the buffer element type matching the FFI parameter.
    let mut fp = [0 as c_char; 16];
    // SAFETY: pointer + length describe `s`; fp is a valid 16-byte buffer.
    let r = unsafe { libinjection_sqli(s.as_ptr() as *const c_char, s.len(), fp.as_mut_ptr()) };
    // libinjection's `injection_result_t` is { FALSE=0, TRUE=1, ERROR=-1 }.
    // Treating anything but 1 as benign means a `-1` error fails open: an
    // intentional choice so a libinjection error never blocks valid traffic.
    r == 1
}

/// Safe wrapper: is `s` cross-site scripting?
///
/// Takes raw bytes for the same reason as [`is_sqli`].
pub fn is_xss(s: &[u8]) -> bool {
    // SAFETY: pointer + length describe `s`.
    let r = unsafe { libinjection_xss(s.as_ptr() as *const c_char, s.len()) };
    // As in `is_sqli`: a `-1` error return is intentionally treated as
    // benign (fail-open) rather than blocking the request.
    r == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sqli() {
        assert!(is_sqli(b"1' OR '1'='1"));
        assert!(is_sqli(b"'; DROP TABLE users; --"));
    }

    #[test]
    fn detects_xss() {
        assert!(is_xss(b"<script>alert(1)</script>"));
    }

    #[test]
    fn passes_benign_input() {
        assert!(!is_sqli(b"hello world"));
        assert!(!is_xss(b"hello world"));
    }

    /// Regression guard for NEW-I2: a non-UTF-8 SQLi payload must still
    /// trigger libinjection. Pre-fix the byte sequence was lossied to
    /// `String` before reaching this wrapper, replacing the high-bit
    /// SHIFT-JIS bytes with U+FFFD and masking the attack.
    #[test]
    fn detects_sqli_in_non_utf8_bytes() {
        // SHIFT-JIS for 'と' followed by a literal SQLi tail; the high
        // bytes 0x82 0xC6 are invalid UTF-8 (would lossy to ?? before).
        let mut payload: Vec<u8> = vec![0x82, 0xc6];
        payload.extend_from_slice(b" 1' OR '1'='1");
        assert!(is_sqli(&payload), "must detect SQLi despite non-UTF-8 prefix");
    }
}
