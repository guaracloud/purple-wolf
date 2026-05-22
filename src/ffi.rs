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
pub fn is_sqli(s: &str) -> bool {
    let mut fp = [0i8; 16];
    // SAFETY: pointer + length describe `s`; fp is a valid 16-byte buffer.
    let r = unsafe { libinjection_sqli(s.as_ptr() as *const c_char, s.len(), fp.as_mut_ptr()) };
    r == 1
}

/// Safe wrapper: is `s` cross-site scripting?
pub fn is_xss(s: &str) -> bool {
    // SAFETY: pointer + length describe `s`.
    let r = unsafe { libinjection_xss(s.as_ptr() as *const c_char, s.len()) };
    r == 1
}

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
