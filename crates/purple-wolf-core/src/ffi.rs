//! FFI bindings for vendored libinjection. This is the only `unsafe` boundary.

#[cfg(not(purple_wolf_no_libinjection))]
use std::os::raw::{c_char, c_int};

#[cfg(not(purple_wolf_no_libinjection))]
extern "C" {
    /// Returns 1 if `input` looks like SQL injection. `fingerprint` must be a
    /// buffer of at least 8 bytes; libinjection writes the matched fingerprint.
    fn libinjection_sqli(input: *const c_char, slen: usize, fingerprint: *mut c_char) -> c_int;

    /// Returns 1 if `input` looks like cross-site scripting.
    fn libinjection_xss(input: *const c_char, slen: usize) -> c_int;
}

/// Safe wrapper: is `s` SQL injection?
#[cfg(not(purple_wolf_no_libinjection))]
pub fn is_sqli(s: &str) -> bool {
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
#[cfg(not(purple_wolf_no_libinjection))]
pub fn is_xss(s: &str) -> bool {
    // SAFETY: pointer + length describe `s`.
    let r = unsafe { libinjection_xss(s.as_ptr() as *const c_char, s.len()) };
    // As in `is_sqli`: a `-1` error return is intentionally treated as
    // benign (fail-open) rather than blocking the request.
    r == 1
}

#[cfg(not(purple_wolf_no_libinjection))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sqli() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("'; DROP TABLE users; --"));
    }

    #[test]
    fn detects_xss() {
        assert!(is_xss("<script>alert(1)</script>"));
    }

    #[test]
    fn passes_benign_input() {
        assert!(!is_sqli("hello world"));
        assert!(!is_xss("hello world"));
    }
}

#[cfg(purple_wolf_no_libinjection)]
pub fn is_sqli(_s: &str) -> bool { false }

#[cfg(purple_wolf_no_libinjection)]
pub fn is_xss(_s: &str) -> bool { false }
